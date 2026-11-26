FROM node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee AS console
RUN --mount=type=tmpfs,target=/var/cache/apt/archives \
    apt-get -o APT::Update::Error-Mode=any update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends --no-remove upgrade \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /console
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72 AS application
COPY --from=ghcr.io/astral-sh/uv:0.13.10@sha256:a3ea1357342c1a4bf9a0c53a3deb1b55379aefa037338d8113d5771efa01774f /uv /usr/local/bin/uv
RUN --mount=type=tmpfs,target=/var/cache/apt/archives \
    --mount=type=bind,source=deploy/check-bookworm-security.sh,target=/tmp/check-bookworm-security.sh \
    apt-get -o APT::Update::Error-Mode=any update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends --no-remove install git openssh-client ca-certificates \
    && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends --no-remove upgrade \
    && sh /tmp/check-bookworm-security.sh \
    && rm -rf /var/lib/apt/lists/*
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
