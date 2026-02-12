# Nebula Panel Runbook

## Service Status

```bash
systemctl status nebula-agent nebula-api nebula-worker nebula-web
journalctl -u nebula-api -f
```

## Common Incidents

1. API returns `401 invalid signature` to agent tasks
- Verify `NEBULA_AGENT_SHARED_SECRET` is identical for API, worker, and agent.

2. Web UI loads but API calls fail
- Verify `NEXT_PUBLIC_NEBULA_API_URL` in `/etc/nebula-panel/secrets.env`.
- Restart `nebula-web` and `nginx`.

3. SSL issuance fails
- Ensure A record points to server and port 80 is reachable.
- Ensure `NEBULA_ACME_WEBROOT` is served at `/.well-known/acme-challenge/`.
- Retry `POST /v1/sites/{id}/ssl/issue`.

4. Mail delivery issues
- Check Postfix + Dovecot status and TLS cert paths.
- Verify generated files exist:
  - `/etc/postfix/virtual_mailbox_domains`
  - `/etc/postfix/virtual_mailbox_maps`
  - `/etc/postfix/virtual_alias_maps`
  - `/etc/dovecot/nebula-users`
- Verify SPF/DKIM/DMARC records in DNS zone.

## Backup Recovery

1. Trigger restore API:
- `POST /v1/backups/{id}/restore`
2. Watch job status:
- `GET /v1/jobs/{id}`
3. Validate site files + database connectivity after restore.
