# Nebula Panel Deployment Guide

## 1) Local Build

```bash
cd /Users/ayaan/Downloads/Nebula
make dev-up
make migrate
make test
make build
```

## 2) Server Requirements

- Ubuntu 22.04 or 24.04
- Root SSH access
- Static public IP
- Open ports: `22, 80, 443, 25, 465, 587, 143, 993, 53/tcp, 53/udp`

## 3) Install on VPS

Copy repo to server, then run:

```bash
cd /opt/src/Nebula
sudo bash deploy/install.sh
```

Installer actions include PostgreSQL role/database creation and applying all SQL migrations in `apps/api/migrations`.

## 4) Configure Secrets

Edit `/etc/nebula-panel/secrets.env`:

- Set strong `NEBULA_ADMIN_PASSWORD`
- Set `NEBULA_ADMIN_TOTP_CODE`
- Set `NEBULA_DATABASE_URL` if your DB host differs
- Set `NEBULA_PDNS_API_KEY`
- Set `NEBULA_ACME_EMAIL`
- Set ZeroSSL EAB values if using fallback (`NEBULA_ZEROSSL_EAB_KID`, `NEBULA_ZEROSSL_EAB_HMAC_KEY`)
- Set `NEXT_PUBLIC_NEBULA_API_URL` to `/v1` (recommended behind Nebula web rewrite)

Then restart:

```bash
sudo systemctl restart nebula-agent nebula-api nebula-worker nebula-web nginx
```

## 5) DNS + SSL

- Create glue records for `ns1.<your-domain>` and `ns2.<your-domain>` to VPS IP.
- Update `/etc/nginx/sites-available/nebula-panel.conf` `server_name`.
- Run cert issuance once domain resolves:

```bash
sudo certbot --nginx -d panel.your-domain.com
```

## 6) Smoke Validation

```bash
curl -s http://127.0.0.1:8080/healthz
sudo bash scripts/verify-stack.sh
```

## 7) Upgrade

```bash
cd /opt/src/Nebula
make build
sudo bash deploy/upgrade.sh
```

## 8) GitHub Actions Auto Deploy (Main Branch)

Repository workflow: `/Users/ayaan/Downloads/Nebula/.github/workflows/deploy.yml`

Behavior:
- Triggers automatically after `ci` succeeds on `main`.
- Also supports manual run from Actions tab (`workflow_dispatch`).
- Builds Linux binaries in GitHub Actions, uploads release to VPS, then runs:
  - `deploy/install.sh` on first install (or when forced)
  - `deploy/upgrade.sh` on existing installations

Required GitHub repository secrets:
- `VPS_HOST`: server IP or hostname
- `VPS_USER`: SSH user (must have passwordless `sudo` for deploy commands, or be root)
- `VPS_SSH_KEY`: private key for the deploy user
- `VPS_PORT`: optional (defaults to `22`)
- `VPS_DEPLOY_DIR`: optional source sync directory on VPS (defaults to `/opt/src/Nebula`)
- `VPS_GOARCH`: optional target architecture for Go binaries (`amd64` or `arm64`, defaults to `amd64`)

Recommended one-time VPS prep:
```bash
sudo adduser --disabled-password --gecos "" nebula-deploy
sudo usermod -aG sudo nebula-deploy
echo "nebula-deploy ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/nebula-deploy
sudo chmod 440 /etc/sudoers.d/nebula-deploy
sudo mkdir -p /home/nebula-deploy/.ssh
sudo chmod 700 /home/nebula-deploy/.ssh
```

Then add your deploy public key:
```bash
sudo tee -a /home/nebula-deploy/.ssh/authorized_keys >/dev/null
sudo chown -R nebula-deploy:nebula-deploy /home/nebula-deploy/.ssh
sudo chmod 600 /home/nebula-deploy/.ssh/authorized_keys
```

First deployment flow:
1. Add secrets in GitHub: Settings -> Secrets and variables -> Actions.
2. Open Actions -> `deploy` -> Run workflow.
3. Set `force_install=true` for the first run.
4. After first install, keep `force_install=false` (default) for upgrade runs.
