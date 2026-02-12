# VS Code Setup and Deployment Flow

## 1. Open Project

- Open folder: `/Users/ayaan/Downloads/Nebula`
- Recommended extensions:
  - Go (golang.go)
  - ESLint
  - Prettier
  - YAML

## 2. Install Local Toolchain

- Go 1.22+
- Node.js 20+
- Docker
- `psql` client (optional if you prefer local `psql`; `make migrate` can also use Dockerized `psql`)

## 3. First Local Run

```bash
cp env.example .env
# macOS/local dev safe paths (no root writes)
cat <<'EOF' >> .env
NEBULA_DATA_ROOT=/Users/ayaan/Downloads/Nebula/.tmp/data
NEBULA_AGENT_SOCKET=/Users/ayaan/Downloads/Nebula/.tmp/nebula-agent.sock
NEBULA_ACME_WEBROOT=/Users/ayaan/Downloads/Nebula/.tmp/acme-webroot
NEBULA_GENERATED_CONFIG_DIR=/Users/ayaan/Downloads/Nebula/.tmp/generated
EOF

make dev-up
make migrate
make test
make build
```

Run services in separate terminals:

```bash
make run-agent
make run-api
make run-worker
make run-web
```

## 4. Login Test

1. Open `http://localhost:3000/login`
2. Use:
   - Email: `admin@localhost`
   - Password: `admin123!`
   - TOTP: not required by default (enable in `Settings -> Security` after login)

## 5. Production Build Artifacts

```bash
make build
```

This generates:
- `bin/nebula-api`
- `bin/nebula-agent`
- `bin/nebula-worker`

## 6. Deploy to Ubuntu VPS

1. Recommended one-command installer from GitHub:

```bash
curl -fsSL https://github.com/nebulapanel/nebula-panel/releases/latest/download/get.sh | sudo bash
```

2. Manual alternative (if repo already exists on server):

```bash
sudo bash deploy/install.sh
```

3. Restart:

```bash
sudo systemctl restart nebula-agent nebula-api nebula-worker nebula-web nginx
```

4. Validate:

```bash
curl -s http://127.0.0.1:8080/healthz
sudo bash scripts/verify-stack.sh
```
