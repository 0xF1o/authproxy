# authproxy

A minimal reverse proxy for HTTP with pin-based authentication. Unauthenticated
visitors see a small form; after entering the correct pin a cookie is set and
all requests are forwarded to the target.

Written in Go (stdlib only), ships as a `FROM scratch` container.

## Environment variables

| Variable      | Required | Default          | Description                              |
| ------------- | -------- | ---------------- | ---------------------------------------- |
| `AUTH_PIN`    | yes      | —                | The pin that must be entered             |
| `TARGET`      | yes      | —                | Upstream URL to proxy to, e.g. `http://localhost:3000` |
| `COOKIE_NAME` | no       | `auth_pin`       | Name of the session cookie               |

The proxy always listens on port `8473` in the container.

## Usage

### With podman compose (includes a `traefik/whoami` target for testing)

```sh
AUTH_PIN=1234 podman compose up -d --build
```

Then open <http://127.0.0.1:8473/> and enter the pin.
The `whoami` service is also exposed directly on port 80 for reference.

Note: rootless podman cannot bind privileged port 80 unless
`net.ipv4.ip_unprivileged_port_start=80` is set on the machine.

### Standalone

```sh
go build -o authproxy .
AUTH_PIN=1234 TARGET=http://localhost:3000 ./authproxy
```

### Dockerfile

Multi-stage: builds a static binary (`CGO_ENABLED=0`) with the `golang` image,
final stage is `FROM scratch` with the CA bundle copied in (needed for HTTPS
targets) and runs as `nobody`.

## How authentication works

- **Login:** the form POSTs the pin to the current URL. It is compared in constant time
  and on success a cookie is set and the browser is redirected back to the
  originally requested path (query string preserved).
- **Cookie value:** the cookie never contains the pin. It stores
  `hex(sha256(salt || pin))` where `salt` is a random 16-byte value generated
  at startup. The salt prevents offline brute-forcing of the pin from a leaked
  cookie; the trade-off is that all sessions are invalidated when the proxy
  restarts (you must enter the pin again).
- **Requests:** a valid cookie is accepted in constant time and the request is
  forwarded; anything else gets the login page (HTTP 200, so browsers render
  it instead of a proxy-auth error dialog).

## Security notes

- The pin travels and is compared in plaintext over the connection. Run behind
  TLS (or on localhost/trusted networks only).
- `read_only: true` in the compose file; the container runs as `nobody`.
- No rate limiting on pin attempts — keep it on a trusted network if the pin
  is short.
