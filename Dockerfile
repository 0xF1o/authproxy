FROM golang:1.25 AS build
WORKDIR /src

# 1. Restore dependency metadata first (cacheable layer)
COPY go.mod ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# 2. Copy source code (invalidates only the build layer)
COPY main.go login.html ./

# 3. Build with cache mounts for fast rebuilds
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /authproxy .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /authproxy /authproxy
USER 65534:65534
EXPOSE 8473
ENTRYPOINT ["/authproxy"]
