# syntax=docker/dockerfile:1

# Build stage. BUILDPLATFORM keeps the compiler running natively while
# cross-compiling for TARGETPLATFORM, which is far faster than emulation.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build

WORKDIR /src

# Dependencies first, so a source-only change does not re-download the module
# cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

# CGO_ENABLED=0 produces a static binary, which is what lets the final image be
# scratch-thin and free of libc CVEs.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/gluetun-proton-updater ./cmd/gluetun-proton-updater

# Runtime stage.
FROM alpine:3.21

# ca-certificates is required for TLS to the Proton API; tzdata makes the TZ
# environment variable work so dashboard timestamps match the host.
RUN apk add --no-cache ca-certificates tzdata wget && \
    addgroup -g 1000 -S updater && \
    adduser -u 1000 -S -G updater updater

COPY --from=build /out/gluetun-proton-updater /usr/local/bin/gluetun-proton-updater

# /data holds the Proton session, the cached server list and the switch history.
# /gluetun is where Gluetun's servers.json lives; mount the same volume Gluetun
# uses.
RUN mkdir -p /data /gluetun && chown -R updater:updater /data

# Runs as root by default, deliberately.
#
# This container has to replace servers.json inside Gluetun's own volume, and
# Gluetun (which needs NET_ADMIN, so runs as root) creates that directory as
# root:root 0755. A non-root process cannot create files there, so it would fail
# to write the one file that makes this tool useful - and the same applies to a
# bind mount owned by the host user.
#
# To run unprivileged instead, arrange ownership yourself and override the user:
#   user: "1000:1000"           # in docker-compose.yml
#   chown -R 1000:1000 <paths>  # on the host, for bind mounts
# The image already contains a uid 1000 "updater" account for that purpose, and
# a startup pre-flight check reports precisely which paths are not writable.
WORKDIR /data

# No ENV defaults here, deliberately.
#
# The three that used to be set repeated defaults the code already has, so they were two places
# to change one value. They also made the dashboard's settings panel report them as configured,
# which was true (the image did set them) and misleading (the operator had not).
#
# One of them had gone stale as well: the servers-file variable was renamed during the move to
# GLUETUN_-prefixed names, so the image went on setting something the program no longer read.
# Nothing failed, because nothing was checking - a test now scans this file for variable names
# the program does not define, which is why the old name is not spelled out here.

EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=5s --start-period=45s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/gluetun-proton-updater"]
