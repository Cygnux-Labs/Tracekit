# The compose stack's witness: omniwitness (github.com/transparency-dev/witness, Apache-2.0) from a pinned commit, or
# litewitness (filippo.io/torchwood, BSD-3-Clause) with --build-arg WITNESS=litewitness. Go fetches both through the
# checksum database, so the pinned version is the code that runs. docs/deploy-compose.md.
# golang:1.27-alpine and alpine:3.24.1 (multi-arch indexes), pinned by digest
ARG GO=golang:1.27-alpine@sha256:738d1cf061836894ff6bb8c33881080ac66de8cf0586615012a0c8f592649cfa
ARG BASE=alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

FROM ${GO} AS build
ARG WITNESS=omniwitness
ARG OMNIWITNESS=b4c9458d9b14e5789285c5b68a7535d152c98de9
ARG TORCHWOOD=v0.10.0
ENV CGO_ENABLED=0 GOBIN=/out
RUN case "$WITNESS" in \
      omniwitness) go install "github.com/transparency-dev/witness/cmd/omniwitness@$OMNIWITNESS" ;; \
      litewitness) go install "filippo.io/torchwood/cmd/litewitness@$TORCHWOOD" "filippo.io/torchwood/cmd/witnessctl@$TORCHWOOD" ;; \
      *) echo "WITNESS is omniwitness or litewitness" >&2; exit 1 ;; \
    esac

FROM ${BASE}
ARG WITNESS=omniwitness
RUN if [ "$WITNESS" = litewitness ]; then apk add --no-cache openssh-client; fi \
 && addgroup -g 10002 witness && adduser -D -H -u 10002 -G witness -s /sbin/nologin witness \
 && install -d -o 10002 -g 10002 -m 0700 /data
COPY --from=build /out/ /usr/local/bin/
COPY entrypoint.sh /usr/local/bin/witness-entrypoint
VOLUME ["/data"]
USER 10002:10002
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/witness-entrypoint"]
