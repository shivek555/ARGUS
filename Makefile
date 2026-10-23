.PHONY: test poc api dashboard-install dashboard-dev dashboard-build serve

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
