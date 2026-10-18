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

- **Login:** the page renders the server's public RSA key (JWK) and a random
  single-use nonce. JavaScript encrypts `{"n":<nonce>,"pin":<pin>}` with
  RSA-OAEP-256 and POSTs the base64url ciphertext as `pin_enc`. The server
  decrypts it, checks the nonce, compares the pin in constant time and on
  success sets a cookie and replies `{"ok":true}` (the page then reloads into
  the target). Plaintext pins are not accepted at all.
- **Why not WebCrypto:** `crypto.subtle` only exists in secure contexts (HTTPS
  or localhost), so it cannot be used on plain HTTP. The login page therefore
  ships a tiny (about 1.5 KB) RSA-OAEP encryptor: SHA-256, MGF1 and a BigInt
  modexp. Only `crypto.getRandomValues` is used, which works on insecure
  origins too.
- **Key lifetime:** the RSA key pair is generated at start and never leaves the
  process, so a recorded ciphertext cannot be decrypted after a restart. A page
  whose key went stale gets "Encryption key expired, please reload".
- **Nonces:** each login page carries a 16-byte nonce (5 min TTL, burned on a
  successful login), so a captured ciphertext cannot be replayed.
- **Cookie value:** the cookie never contains the pin. It stores
  `hex(sha256(salt || pin))` where `salt` is a random 16-byte value generated
  at startup. The salt prevents offline brute-forcing of the pin from a leaked
  cookie; the trade-off is that all sessions are invalidated when the proxy
  restarts (you must enter the pin again).
- **Requests:** a valid cookie is accepted in constant time and the request is
  forwarded; anything else gets the login page (HTTP 200, so browsers render
  it instead of a proxy-auth error dialog).

## Security notes

- This protects against **passive** eavesdropping: someone sniffing the wire
  sees only RSA ciphertext (the encrypted payload is padded to the key size, so
  the pin length is hidden as well).
- It does **not** protect against an active man-in-the-middle, who can just
  serve their own login page with their own key. For real protection put the
  proxy behind TLS (or use it on localhost/trusted networks only).
- Login requires JavaScript; there is no plaintext fallback.
- `read_only: true` in the compose file; the container runs as `nobody`.
- No rate limiting on pin attempts — keep it on a trusted network if the pin
  is short.
