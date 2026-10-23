from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from argus.api.models import CreateSessionRequest, ToolCallRequest
from argus.api.service import ROOT, ArgusService, Conflict, NotFound

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


def create_app(service: ArgusService | None = None, dist: Path = DIST) -> FastAPI:
    app = FastAPI(
        title="ARGUS API",
        version="0.1.0",
        description=(
            "Local research API over the ARGUS PoC: frozen scenario replays, the logged "
            "PoC evaluation, and an enforce-mode gateway playground against fake tools."
        ),
    )
    app.add_middleware(SecurityHeaders)
    svc = service or ArgusService()
    app.state.service = svc

    @app.exception_handler(NotFound)
    async def _not_found(_: Request, exc: NotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": f"not found: {exc.args[0]}"})

    @app.exception_handler(Conflict)
    async def _conflict(_: Request, exc: Conflict) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/meta")
    def meta() -> dict[str, Any]:
        return svc.meta()

    @app.get("/api/scenarios")
    def scenarios() -> list[dict[str, Any]]:
        return svc.list_scenarios()

    @app.get("/api/scenarios/{scenario_id}")
    def scenario(scenario_id: str) -> dict[str, Any]:
        return svc.scenario_detail(scenario_id)

    @app.get("/api/experiments/poc")
    def experiment() -> dict[str, Any]:
        result = svc.experiment()
        if result is None:
            raise HTTPException(
                status_code=404,
                detail="TODO: not yet measured. Run `python -m argus.eval.poc` (or POST /api/experiments/poc/run).",
            )
        return result

    @app.post("/api/experiments/poc/run")
    def run_experiment() -> dict[str, Any]:
        return svc.run_experiment()

    @app.post("/api/sessions", status_code=201)
    def create_session(body: CreateSessionRequest) -> dict[str, Any]:
        return svc.create_session(
            scenario_id=body.scenario_id,
            objective_text=body.objective_text,
            allowed_scopes=body.allowed_scopes,
        )

    @app.get("/api/sessions/{session_id}")
    def get_session(session_id: str) -> dict[str, Any]:
        return svc.session_state(session_id)

    @app.post("/api/sessions/{session_id}/calls")
    def call_tool(session_id: str, body: ToolCallRequest) -> dict[str, Any]:
        return svc.invoke(session_id, body)

    @app.post("/api/sessions/{session_id}/script/next")
    def script_next(session_id: str) -> dict[str, Any]:
        return svc.advance_script(session_id)

    @app.delete("/api/sessions/{session_id}", status_code=204, response_class=Response)
    def delete_session(session_id: str) -> Response:
        svc.delete_session(session_id)
        return Response(status_code=204)

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
                detail="dashboard not built: run `npm --prefix dashboard install && npm --prefix dashboard run build`",
            )
        candidate = (root / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(root):
            return FileResponse(candidate)
        return FileResponse(index)
