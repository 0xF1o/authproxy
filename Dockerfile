FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod .
COPY main.go crypto.go login.html .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /authproxy .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /authproxy /authproxy
USER 65534:65534
EXPOSE 8473
ENTRYPOINT ["/authproxy"]
