# syntax=docker/dockerfile:1
#
# Runs mailcloak-bridge as the mailcloak user. Mount the config directory
# (mailcloak.yaml, keys and the TLS certificate) at
# /etc/mailcloak, and keep /var/lib/mailcloak and /var/cache/mailcloak-bridge
# on volumes. The cache holds decrypted mail.
#
#   docker run -v /etc/mailcloak:/etc/mailcloak:ro -v mailcloak-state:/var/lib/mailcloak \
#     -v mailcloak-cache:/var/cache/mailcloak-bridge -p 993:993 -p 465:465 mailcloak-bridge

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "${VERSION:+-X github.com/brodyhoskins/mailcloak-bridge/internal/version.Version=$VERSION}" \
      -o /out/ ./cmd/...

FROM alpine:3
RUN apk add --no-cache ca-certificates libcap \
 && addgroup -S mailcloak \
 && adduser -S -D -H -G mailcloak -h /var/lib/mailcloak -s /sbin/nologin mailcloak \
 && install -d -o mailcloak -g mailcloak -m 0750 /var/lib/mailcloak \
 && install -d -o mailcloak -g mailcloak -m 0700 /var/cache/mailcloak-bridge

COPY --from=build /out/ /usr/local/bin/
# Ports 993 and 465 without root.
RUN setcap cap_net_bind_service=+ep /usr/local/bin/mailcloak-bridge && apk del libcap

USER mailcloak
ENV STATE_DIRECTORY=/var/lib/mailcloak CACHE_DIRECTORY=/var/cache/mailcloak-bridge
VOLUME ["/var/lib/mailcloak", "/var/cache/mailcloak-bridge"]
EXPOSE 993 465
ENTRYPOINT ["mailcloak-bridge", "-config", "/etc/mailcloak/mailcloak.yaml"]
