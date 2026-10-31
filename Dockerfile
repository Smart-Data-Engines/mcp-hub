FROM node:25-bookworm-slim AS console
WORKDIR /console
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.15-slim-bookworm AS application
COPY --from=ghcr.io/astral-sh/uv:0.13.1 /uv /usr/local/bin/uv
RUN --mount=type=tmpfs,target=/var/cache/apt/archives apt-get update && apt-get install -y --no-install-recommends git openssh-client ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=tmpfs,target=/tmp uv export --frozen --no-dev --no-emit-project --format requirements-txt --output-file /tmp/requirements.txt && uv pip install --system --no-cache --require-hashes -r /tmp/requirements.txt
COPY src/ ./src/
RUN --mount=type=tmpfs,target=/tmp uv pip install --system --no-cache --no-deps . && python -c "from mcp_hub.cli import main; from mcp_hub.app import create_app; assert callable(main) and callable(create_app)" && groupadd --gid 10001 hub && useradd --uid 10001 --gid hub --no-create-home hub
COPY --from=console /console/dist /app/console
ENV FRONTEND_DIR=/app/console PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
LABEL io.smartdataengines.mcp-hub=controller
USER 10001:10001
EXPOSE 8000 8001
CMD ["mcp-hub", "serve"]

FROM application AS upstream
CMD ["python", "-m", "mcp_hub.runner"]
