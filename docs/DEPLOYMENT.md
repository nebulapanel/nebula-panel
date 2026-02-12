# Nebula Panel Deployment Guide

## 1) VPS Requirements

- Ubuntu `22.04` or `24.04`
- Root SSH access (or sudo user)
- Static public IP
- Open ports: `22, 80, 443, 25, 465, 587, 143, 993, 53/tcp, 53/udp`

## 2) Fast Install (One Command)

On a fresh Ubuntu VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/nebulapanel/nebula-panel/main/scripts/install-ubuntu.sh | sudo bash
```

This script:
- Clones source into `/opt/src/Nebula`
- Installs required packages
- Installs modern Go if needed
- Builds Nebula binaries
- Runs `deploy/install.sh`

## 3) Manual Install (Alternative)

```bash
git clone https://github.com/nebulapanel/nebula-panel.git /opt/src/Nebula
cd /opt/src/Nebula
sudo bash deploy/install.sh
```

`deploy/install.sh` now builds binaries automatically on server, so separate `make build` is not required for production install.

## 4) Post-Install Required Changes

Edit:

```bash
sudo nano /etc/nebula-panel/secrets.env
```

Set at minimum:
- `NEBULA_ADMIN_EMAIL`
- `NEBULA_ADMIN_PASSWORD`
- `NEBULA_ADMIN_TOTP_CODE` (do not keep `000000`)
- `NEBULA_ACME_EMAIL`
- `NEBULA_PDNS_API_KEY`
- `NEBULA_APP_KEY` (32-byte hex or base64; used to encrypt secrets at rest)
- `NEBULA_ZEROSSL_EAB_KID` and `NEBULA_ZEROSSL_EAB_HMAC_KEY` (if using ZeroSSL fallback)

Recommended for DNS hosting:
- `NEBULA_NS1_FQDN`, `NEBULA_NS2_FQDN` (your global nameservers)
- `NEBULA_PUBLIC_IPV4` (auto-detected on install; used to seed nameserver A records when applicable)

Restart services:

```bash
sudo systemctl restart nebula-agent nebula-api nebula-worker nebula-web nginx
```

Validate:

```bash
curl -s http://127.0.0.1:8080/healthz
sudo bash /opt/src/Nebula/scripts/verify-stack.sh
```

Provisioning model (important):
- The API enqueues jobs in Postgres (`queued`)
- `nebula-worker` picks them up and runs privileged tasks via `nebula-agent`
- Track progress using:
  - `GET /v1/jobs`
  - `GET /v1/jobs/{id}`
  - `GET /v1/jobs/{id}/events`

Panel URL (default):
- `http://<your-server-ip>/`

## 5) DNS + SSL Go-Live

- If you run your own nameservers, create glue records for your chosen nameserver hostnames:
  - `NEBULA_NS1_FQDN` -> VPS IP
  - `NEBULA_NS2_FQDN` -> VPS IP
- Update `server_name` in `/etc/nginx/sites-available/nebula-panel.conf`
- Reload Nginx:
  - `sudo systemctl reload nginx`
- Issue panel certificate (optional for panel hostname):

```bash
sudo certbot --nginx -d panel.your-domain.com
```

## 6) Upgrade Existing Install

```bash
cd /opt/src/Nebula
git pull --ff-only
sudo bash deploy/upgrade.sh
```

`deploy/upgrade.sh` now builds binaries automatically before upgrade.

## 7) GitHub Actions Auto Deploy

Workflow file:
- `.github/workflows/deploy.yml`

How it behaves:
1. `ci` runs on push/PR.
2. If CI succeeds on `main` push, `deploy` auto-runs.
3. `deploy` builds Linux binaries, uploads release archive to VPS, and runs install/upgrade remotely.
4. If required secrets are not configured:
   - auto-triggered deploy is skipped with a notice (not a hard failure)
   - manual deploy fails with a clear missing-secrets message

### Required Secrets

Add in GitHub: `Settings -> Secrets and variables -> Actions`

| Secret | Required | Example | Purpose |
|---|---|---|---|
| `VPS_HOST` | yes | `203.0.113.10` | VPS SSH host/IP |
| `VPS_USER` | yes | `nebula-deploy` | SSH user used by Actions |
| `VPS_SSH_KEY` | yes | multi-line private key | Private key matching VPS authorized key |
| `VPS_PORT` | no | `22` | SSH port |
| `VPS_DEPLOY_DIR` | no | `/opt/src/Nebula` | Directory where release archive is extracted |
| `VPS_GOARCH` | no | `amd64` or `arm64` | Target Linux binary arch for Go build |

Choose `VPS_GOARCH`:

```bash
uname -m
```

- If output is `x86_64` -> use `amd64`
- If output is `aarch64` or `arm64` -> use `arm64`

### One-Time SSH Setup for Actions

On your local machine:

```bash
ssh-keygen -t ed25519 -C "nebula-github-actions" -f ~/.ssh/nebula_actions -N ""
cat ~/.ssh/nebula_actions.pub
```

On VPS (as root/sudo):

```bash
sudo adduser --disabled-password --gecos "" nebula-deploy
sudo usermod -aG sudo nebula-deploy
echo "nebula-deploy ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/nebula-deploy
sudo chmod 440 /etc/sudoers.d/nebula-deploy
sudo mkdir -p /home/nebula-deploy/.ssh
sudo chmod 700 /home/nebula-deploy/.ssh
```

Paste the public key into:

```bash
sudo tee -a /home/nebula-deploy/.ssh/authorized_keys >/dev/null
sudo chown -R nebula-deploy:nebula-deploy /home/nebula-deploy/.ssh
sudo chmod 600 /home/nebula-deploy/.ssh/authorized_keys
```

Add private key to GitHub secret `VPS_SSH_KEY`:

```bash
cat ~/.ssh/nebula_actions
```

Copy full key text including:
- `-----BEGIN OPENSSH PRIVATE KEY-----`
- `-----END OPENSSH PRIVATE KEY-----`

## 8) First GitHub Deploy Run

1. Push latest `main`.
2. Open `Actions -> deploy -> Run workflow`.
3. Set `force_install=true` for first run.
4. Later runs should keep `force_install=false` (default).

## 9) Troubleshooting

Check workflow logs:
- GitHub Actions -> `deploy` run -> failed step details

Check server logs:

```bash
sudo journalctl -u nebula-agent -u nebula-api -u nebula-worker -u nebula-web -n 200 --no-pager
```

Check service status:

```bash
sudo systemctl status nebula-agent nebula-api nebula-worker nebula-web --no-pager
```
