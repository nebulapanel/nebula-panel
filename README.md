# Nebula Panel

Nebula Panel is a single-server hosting control panel with web, DNS, SSL, files, mail, backups, and webmail modules.

## Monorepo Layout

- `apps/api` - REST API and orchestration layer
- `apps/worker` - async jobs (SSL renewal, backups, health checks)
- `apps/agent` - privileged local executor over Unix socket
- `apps/web` - Next.js admin + webmail UI
- `packages/contracts` - OpenAPI and shared contracts
- `deploy` - installer, upgrade scripts, systemd units, templates

## Quick Start (Local)

1. Install Go 1.22+, Node 20+, Docker.
2. Start dev dependencies:
   - `make dev-up`
3. Apply database migrations:
   - `make migrate`
4. Build and test:
   - `make build`
   - `make test`
5. Run services:
   - `make run-agent`
   - `make run-api`
   - `make run-worker`
   - `make run-web`

## Production Install (Ubuntu, one command)

Use this on a fresh Ubuntu 22.04/24.04 VPS:

```bash
curl -fsSL https://github.com/nebulapanel/nebula-panel/releases/latest/download/get.sh | sudo bash
```

What it does:
- Downloads the latest signed release archive and verifies SHA256
- Extracts source to `/opt/src/Nebula`
- Installs dependencies (Nginx, PostgreSQL, MariaDB, Redis, PowerDNS, Postfix, Dovecot, OpenDKIM, Fail2ban, Node)
- Uses prebuilt Linux binaries from the release (no Go toolchain required on the VPS)
- Runs `deploy/install.sh`

During install, the terminal prompts you for:
- Admin email
- Admin password (or it generates one and prints it once)

After install:
1. Verify API:
   - `curl -s http://127.0.0.1:8080/healthz`
2. Open the panel:
   - `http://<your-server-ip>/`

## Operations Docs

- `docs/VS_CODE_SETUP.md` - local VS Code setup and deployment flow
- `docs/DEPLOYMENT.md` - production installation and validation
- `docs/RUNBOOK.md` - incident and recovery basics

## License

See `LICENSE`.
