# The stand-in agent image of `tracekit up --isolated` (docs/design/isolated-up.md), from the repo root:
#   docker build -f deploy/box/Dockerfile -t tracekit-box:dev .
# Python, Tracekit (the hooks' client) and Claude Code's managed settings with Tracekit's v2 hooks, which nothing in
# the project can turn off; no Claude Code. deploy/box/stand-in-agent runs Bash calls through those hooks as Claude
# Code would. For Claude Code, build an image FROM this one that installs it. The box runs it as your uid.
# python:3.12-slim-bookworm (multi-arch index), pinned by digest
ARG BASE=python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
FROM ${BASE}
ENV PYTHONDONTWRITEBYTECODE=1 HOME=/home/agent
COPY . /src
RUN PIP_CONSTRAINT="/src/scripts/release/constraints.txt /src/scripts/release/runtime-constraints.txt" \
    pip install --no-cache-dir /src \
 && python -c "from tracekit import install; install.install_hooks('/etc/claude-code/managed-settings.json', \
    module=install.V2_HOOK, python='/usr/local/bin/python', mode=0o644)" \
 && install -m 0755 /src/deploy/box/stand-in-agent /usr/local/bin/stand-in-agent \
 && install -d -m 1777 /home/agent \
 && rm -rf /src
WORKDIR /work
USER 1000:1000
CMD ["bash"]
