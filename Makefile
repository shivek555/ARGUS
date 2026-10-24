.PHONY: install test poc api dashboard-install dashboard-dev dashboard-build serve reproduce reproduce-fast reproduce-check latency

install:
	python -m pip install -r requirements.txt -c constraints.txt

test:
	python -m pytest -q

poc:
	python -m argus.eval.poc

# API only (http://127.0.0.1:8000/docs for the OpenAPI UI).
api:
	python -m argus.api

dashboard-install:
	npm --prefix dashboard ci

# Hot-reloading UI on http://127.0.0.1:5173; proxies /api to `make api`.
dashboard-dev:
	npm --prefix dashboard run dev

dashboard-build:
	npm --prefix dashboard run build

# One origin: built dashboard + API on http://127.0.0.1:8000
serve: dashboard-build
	python -m argus.api

# R4 (ADR-0013): rebuild every results table and figure in docs/results/ from committed inputs.
reproduce:
	python -m argus.eval.reproduce

# Same, without the ~9 min R1b grid (its table stays as committed).
reproduce-fast:
	python -m argus.eval.reproduce --fast

# Rebuild in a temp dir and fail if anything differs from docs/results/ (CI runs this with --fast).
reproduce-check:
	python -m argus.eval.reproduce --check

# Machine-dependent per-call overhead (RQ5); never part of reproduce-check.
latency:
	python -m argus.eval.latency --doc docs/results/latency-local.md
