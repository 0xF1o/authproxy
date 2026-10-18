FROM golang:1.25 AS build

# 0. Install UPX for final binary compression (cacheable layer)
RUN apt-get update && apt-get install -y --no-install-recommends upx-ucl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# 1. Restore dependency metadata first (cacheable layer)
COPY go.mod ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# 2. Copy source code (invalidates only the build layer)
COPY main.go main_test.go login.html ./

# 3. Run tests
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go test ./...

# 4. Build with cache mounts for fast rebuilds
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /authproxy .

# 5. Compress the binary (verified to work with Go 1.25 static builds)
RUN upx --best /authproxy

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /authproxy /authproxy
USER 65534:65534
EXPOSE 8473
ENTRYPOINT ["/authproxy"]
