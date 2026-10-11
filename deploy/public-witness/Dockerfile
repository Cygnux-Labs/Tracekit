# The public witness: `docker build -f deploy/public-witness/Dockerfile .` from the repo root (README.md here).
# The signer image's base: python:3.12-slim-bookworm (multi-arch index), pinned by digest
ARG BASE=python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

FROM ${BASE} AS build
WORKDIR /src
COPY . .
RUN PIP_CONSTRAINT="scripts/release/constraints.txt scripts/release/runtime-constraints.txt" \
    pip wheel --no-cache-dir --wheel-dir /wheels .

FROM ${BASE}
LABEL org.opencontainers.image.source="https://github.com/Cygnux-Labs/Tracekit" \
      org.opencontainers.image.title="tracekit-public-witness" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels \
    pip install --no-cache-dir --no-index /wheels/*.whl \
 && groupadd -g 10001 tracekit \
 && useradd -u 10001 -g 10001 -M -d /nonexistent -s /usr/sbin/nologin tracekit \
 && install -d -o 10001 -g 10001 -m 0700 /data
# /data: witness.key, witness.vkey and state.db, the one volume (back it up)
VOLUME ["/data"]
USER 10001:10001
EXPOSE 7380
ENTRYPOINT ["tracekit", "public-witness"]
CMD ["serve", "--home", "/data", "--host", "0.0.0.0", "--port", "7380", "--insecure-http", "--proxied"]
