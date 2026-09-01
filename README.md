# rustdesk-minimal-api

A tiny single-user RustDesk API server in Go.

All commands below assume you are running them from the root of the standalone `rustdesk-minimal-api` repository.

It intentionally covers only the basics:
- account login/logout
- current user lookup
- legacy address book sync
- a basic device inventory that populates the **Accessible devices** tab
- optional heartbeat/sysinfo ingestion for device discovery (disabled by default)

It is **not** a replacement for RustDesk Server Pro.
It is meant for a small self-hosted setup where you want private login, contacts, and a simple device list.

## Supported endpoints

- `GET /api/login-options`
- `POST /api/login`
- `POST /api/currentUser`
- `POST /api/logout`
- `GET /api/ab`
- `POST /api/ab`
- `POST /api/ab/get`
- `GET /api/users`
- `GET /api/peers`
- `GET /api/device-group/accessible`
- `POST /api/heartbeat`
- `POST /api/sysinfo`
- `GET /healthz`

## What it stores

The server persists a small JSON state file containing:
- a signing secret for access tokens
- a token version counter used to revoke tokens on logout
- the legacy address book JSON blob
- an address book revision counter for conditional updates
- the last address book update timestamp
- device inventory learned from `/api/heartbeat` and `/api/sysinfo`

## Credentials

The server does **not** take a plaintext password on the CLI.
Pass a single credential in this format instead:

```text
username:bcrypt_hash
```

Interactive generator included in this repo. It prompts for a username and password, then prints the final `username:bcrypt_hash` pair:

```bash
go run ./cmd/gen-credential
```

Optional bcrypt cost override:

```bash
go run ./cmd/gen-credential -cost 12
```

Example hash generation with Python:

```bash
python3 - <<'PY'
import bcrypt
print(bcrypt.hashpw(b"change-me", bcrypt.gensalt(rounds=10)).decode())
PY
```

Example hash generation with Go:

```bash
cat <<'EOF' > /tmp/bcrypt.go
package main

import (
    "fmt"
    "log"

    "golang.org/x/crypto/bcrypt"
)

func main() {
    hash, err := bcrypt.GenerateFromPassword([]byte("change-me"), 10)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(string(hash))
}
EOF

go run /tmp/bcrypt.go
```

## Local run

```bash
go run . \
  -listen :21114 \
  -credential 'alice:$2y$10$.....................................................' \
  -display-name 'Alice'
```

Environment variables are also supported:
- `RUSTDESK_API_LISTEN`
- `RUSTDESK_API_CREDENTIAL`
- `RUSTDESK_API_DISPLAY_NAME`
- `RUSTDESK_API_DATA`
- `RUSTDESK_API_TOKEN_TTL`
- `RUSTDESK_API_ENABLE_INVENTORY` (default `false`)
- `RUSTDESK_API_CORS_ORIGIN` (empty by default; wildcard CORS is not enabled)

Example:

```bash
export RUSTDESK_API_CREDENTIAL='alice:$2y$10$.....................................................'
export RUSTDESK_API_DATA=./state.json
go run .
```

For a public deployment, keep the service private and put TLS in front of it:

```bash
export RUSTDESK_API_LISTEN=127.0.0.1:21114
export RUSTDESK_API_ENABLE_INVENTORY=false
go run .
```

Use Caddy or Nginx to proxy `https://YOUR_HOST` to `127.0.0.1:21114`. Do not expose
the plain HTTP listener to the Internet: login passwords and Bearer tokens would
otherwise be sent without transport encryption.

## RustDesk client configuration

### Compatibility mode
If a client has a custom ID server set and leaves the API server empty, RustDesk typically infers:

```text
http://YOUR_HOST:21114
```

If you need the old client's automatic port inference, expose port `21114` only
inside a trusted LAN or through a TLS-capable reverse proxy. Explicitly configured
clients should use `https://YOUR_HOST`.

### Secure mode
For clients you configure explicitly, prefer:

```text
https://YOUR_HOST
```

That gives you TLS via Caddy while keeping the Go service bound to loopback.

## Accessible devices tab

The server can populate `/api/users`, `/api/peers`, and `/api/device-group/accessible`
from device heartbeats/sysinfo when inventory is explicitly enabled.

In practice this means:
- once a RustDesk client points to this API server, it may post heartbeat/sysinfo data
- after you log in, the **Accessible devices** tab can list those devices
- devices remain listed even when offline; the client resolves online/offline status separately
- all discovered devices belong to the single configured user
- inventory is disabled by default because these client uploads are unauthenticated

## Deployment with systemd + Caddy

This layout keeps the API listener private and exposes the service through HTTPS.

### 1. Build and install the binary

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o rustdesk-minimal-api .

sudo install -m 0755 rustdesk-minimal-api /usr/local/bin/rustdesk-minimal-api
sudo useradd --system --home /var/lib/rustdesk-minimal-api --create-home --shell /usr/sbin/nologin rustdeskapi || true
sudo install -d -o rustdeskapi -g rustdeskapi -m 0750 /var/lib/rustdesk-minimal-api
```

### 2. Write the environment file

```bash
sudo tee /etc/default/rustdesk-minimal-api >/dev/null <<'EOF'
RUSTDESK_API_CREDENTIAL='alice:$2y$10$.....................................................'
RUSTDESK_API_DISPLAY_NAME='Alice'
RUSTDESK_API_DATA='/var/lib/rustdesk-minimal-api/state.json'
RUSTDESK_API_TOKEN_TTL='720h'
EOF
sudo chmod 600 /etc/default/rustdesk-minimal-api
```

### 3. Create the systemd unit

```bash
sudo tee /etc/systemd/system/rustdesk-minimal-api.service >/dev/null <<'EOF'
[Unit]
Description=rustdesk-minimal-api
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rustdeskapi
Group=rustdeskapi
EnvironmentFile=/etc/default/rustdesk-minimal-api
WorkingDirectory=/var/lib/rustdesk-minimal-api
ExecStart=/usr/local/bin/rustdesk-minimal-api -listen 127.0.0.1:21114
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
ReadWritePaths=/var/lib/rustdesk-minimal-api

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now rustdesk-minimal-api.service
```

### 4. Configure Caddy for HTTPS

```bash
sudo tee /etc/caddy/Caddyfile >/dev/null <<'EOF'
YOUR_HOST {
    encode zstd gzip
    reverse_proxy 127.0.0.1:21114
}
EOF

sudo systemctl restart caddy
```

### 5. Open firewall ports if needed

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

### Resulting traffic flow

- `https://YOUR_HOST` → Caddy TLS termination → reverse proxy to `127.0.0.1:21114`

## Notes

- Only the legacy address book flow is implemented. The newer shared address book APIs intentionally return `404`.
- `GET /api/ab` returns a `revision` field. Automation can include that revision in
  `POST /api/ab` to receive `409 Conflict` instead of overwriting a newer update.
  Official clients omit it and retain their normal legacy behavior.
- Logout revokes only the token used for that logout; other active devices remain logged in.
- Login attempts are rate-limited per source address. HTTP read/write/header timeouts
  and request body limits are enabled by default.
- Inventory uploads, when enabled, are unauthenticated for compatibility with
  official clients; enable them only on a trusted/private network.

## Test

```bash
go test ./...
```
