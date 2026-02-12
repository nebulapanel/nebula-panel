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

1. Install Go 1.22+, Node 20+, pnpm, Docker.
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

## Production Install

Use `deploy/install.sh` on a fresh Ubuntu 22 VPS.

## Operations Docs

- `docs/VS_CODE_SETUP.md` - local VS Code setup and deployment flow
- `docs/DEPLOYMENT.md` - production installation and validation
- `docs/RUNBOOK.md` - incident and recovery basics

## License

See `LICENSE`.
