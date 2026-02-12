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
