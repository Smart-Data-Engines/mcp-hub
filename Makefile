.PHONY: dev down test check frontend
UV ?= uv
dev:
	python3 scripts/dev.py
down:
	docker compose -f compose.yaml -f compose.demo.yaml down
test:
	$(UV) run --extra dev pytest -m 'not docker and not live'
check:
	python3 scripts/check_private_boundaries.py
	$(UV) run --extra dev ruff check src tests
	$(UV) run --extra dev ruff format --check src tests
	$(UV) run --extra dev mypy src/mcp_hub
	cd frontend && npm run build
frontend:
	cd frontend && npm ci && npm run build
