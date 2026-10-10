# The v2 signer: `docker build -f deploy/docker/Dockerfile .` from the repo root. docs/deploy-container.md.
# python:3.12-slim-bookworm (multi-arch index), pinned by digest
ARG BASE=python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

FROM ${BASE} AS build
WORKDIR /src
COPY . .
# google-re2 only as a binary wheel: where it has none, the signer runs on the regex backend (signed as its engine id);
# psycopg for the Postgres store (storage: {postgres: ...})
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[postgres]" "regex>=2023.8" \
 && { pip wheel --no-cache-dir --only-binary=:all: --wheel-dir /wheels "google-re2>=1.1" \
      || echo "no google-re2 wheel for this platform: the regex backend is used"; }

FROM ${BASE}
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/Cygnux-Labs/Tracekit" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.title="tracekit-signer" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels \
    pip install --no-cache-dir --no-index /wheels/*.whl \
 && groupadd -g 10001 tracekit \
 && useradd -u 10001 -g 10001 -M -d /nonexistent -s /usr/sbin/nologin tracekit \
 && install -d -o 10001 -g 10001 -m 0700 /var/lib/tracekit-signer \
 && install -d -o 10001 -g 10001 -m 0755 /run/tracekit-signer
COPY deploy/docker/signer.yaml.example /etc/tracekit/signer.yaml
VOLUME ["/var/lib/tracekit-signer", "/run/tracekit-signer"]
USER 10001:10001
# 8443: the https listener (central); 9464: metrics. The sidecar's Unix socket is in /run/tracekit-signer.
EXPOSE 8443 9464
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9464/metrics', timeout=4)"]
ENTRYPOINT ["tracekit", "signer", "serve", "--config", "/etc/tracekit/signer.yaml"]
