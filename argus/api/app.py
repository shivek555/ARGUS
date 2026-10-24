from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from argus.api import demo
from argus.api.models import ApprovalRequest, CreateSessionRequest, ToolCallRequest
from argus.api.research import Conflict, Forbidden, NotFound, ResearchService
from argus.api.service import ROOT, ArgusService
from argus.api.service import NotFound as ArchiveNotFound

DIST = ROOT / "dashboard" / "dist"

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    ),
}


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        for key, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        return response


def create_app(research: ResearchService | None = None, archive: ArgusService | None = None,
               dist: Path = DIST) -> FastAPI:
    app = FastAPI(
        title="ARGUS API",
        version="1.0.0",
        description=(
            "Local research API over ARGUS (ADR-0014): AgentEscapeBench replays with frozen R3 risk "
            "decisions and explanations, enforce-mode containment sessions, the human approval queue, "
            "forensic snapshots, and the committed R4 results. The v0 PoC is under /api/archive."
        ),
    )
    app.add_middleware(SecurityHeaders)
    svc = research or ResearchService()
    arc = archive or ArgusService()
    app.state.service, app.state.archive = svc, arc

    @app.exception_handler(NotFound)
    @app.exception_handler(ArchiveNotFound)
    async def _not_found(_: Request, exc: KeyError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": f"not found: {exc.args[0]}"})

    @app.exception_handler(Conflict)
    async def _conflict(_: Request, exc: Conflict) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(Forbidden)
    async def _forbidden(_: Request, exc: Forbidden) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/meta")
    def meta() -> dict[str, Any]:
        return svc.meta()

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        return svc.status()

    # ---- benchmark
    @app.get("/api/bench")
    def bench(split: str | None = Query(None, max_length=32), family: str | None = Query(None, max_length=32),
              variant: str | None = Query(None, max_length=32)) -> list[dict[str, Any]]:
        return svc.list_bench(split, family, variant)

    @app.get("/api/bench/{trajectory_id}")
    def bench_detail(trajectory_id: str) -> dict[str, Any]:
        return svc.bench_detail(trajectory_id)

    # ---- live sessions
    @app.post("/api/sessions", status_code=201)
    def create_session(body: CreateSessionRequest) -> dict[str, Any]:
        return svc.create_session(trajectory_id=body.trajectory_id, objective_text=body.objective_text,
                                  allowed_scopes=body.allowed_scopes)

    @app.get("/api/sessions/{session_id}")
    def get_session(session_id: str) -> dict[str, Any]:
        return svc.session_state(session_id)

    @app.post("/api/sessions/{session_id}/calls")
    def call_tool(session_id: str, body: ToolCallRequest) -> dict[str, Any]:
        return svc.invoke(session_id, body.tool, dict(body.args))

    @app.post("/api/sessions/{session_id}/script/next")
    def script_next(session_id: str) -> dict[str, Any]:
        return svc.advance_script(session_id)

    @app.delete("/api/sessions/{session_id}", status_code=204, response_class=Response)
    def delete_session(session_id: str) -> Response:
        svc.delete_session(session_id)
        return Response(status_code=204)

    # ---- approvals
    @app.get("/api/approvals")
    def approvals() -> dict[str, Any]:
        return svc.approvals()

    @app.post("/api/approvals/{approval_id}")
    def decide(approval_id: str, body: ApprovalRequest) -> dict[str, Any]:
        return svc.decide(approval_id, body.approve, body.reviewer)

    # ---- forensics
    @app.get("/api/forensics")
    def forensics() -> list[dict[str, Any]]:
        return svc.forensics()

    @app.get("/api/forensics/{session_id}")
    def forensic(session_id: str) -> dict[str, Any]:
        return svc.forensic(session_id)

    @app.post("/api/forensics/{session_id}/verify")
    def verify(session_id: str) -> dict[str, Any]:
        return svc.verify(session_id)

    # ---- committed results
    @app.get("/api/results/figures/{name}.svg")
    def figure(name: str) -> FileResponse:
        return FileResponse(svc.figure(name), media_type="image/svg+xml")

    @app.get("/api/results/{name}")
    def result(name: str) -> Any:
        return svc.result(name)

    # ---- demo
    @app.get("/api/demo")
    def demo_beats() -> dict[str, Any]:
        return {"beats": demo.BEATS, "approval_timeout_s": svc.approval_timeout_s}

    @app.post("/api/demo/reset")
    def demo_reset() -> dict[str, str]:
        svc.reset()
        return {"status": "reset", "note": "sessions and approvals cleared; snapshot files stay on disk"}

    # ---- archive (v0 PoC, read-only)
    @app.get("/api/archive/meta")
    def archive_meta() -> dict[str, Any]:
        return arc.meta()

    @app.get("/api/archive/scenarios")
    def archive_scenarios() -> list[dict[str, Any]]:
        return arc.list_scenarios()

    @app.get("/api/archive/scenarios/{scenario_id}")
    def archive_scenario(scenario_id: str) -> dict[str, Any]:
        return arc.scenario_detail(scenario_id)

    @app.get("/api/archive/experiment")
    def archive_experiment() -> dict[str, Any]:
        result = arc.experiment()
        if result is None:
            raise HTTPException(status_code=404,
                                detail="TODO: not yet generated. Run `python -m argus.eval.reproduce`.")
        return result

    _mount_dashboard(app, dist)
    return app


def _mount_dashboard(app: FastAPI, dist: Path) -> None:
    """Serve the built SPA when present. Unknown non-API paths get index.html."""
    index = dist / "index.html"
    root = dist.resolve()

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        if path.startswith("api/") or path == "api":
            raise HTTPException(status_code=404, detail="not found")
        if not index.exists():
            raise HTTPException(
                status_code=404,
                detail="dashboard not built: run `npm --prefix dashboard ci && npm --prefix dashboard run build`",
            )
        candidate = (root / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(root):
            return FileResponse(candidate)
        return FileResponse(index)
