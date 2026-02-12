BEGIN;

-- Associate DNS zones with an owning panel user for RBAC scoping.
ALTER TABLE dns_zones
  ADD COLUMN IF NOT EXISTS owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL;

UPDATE dns_zones
SET owner_user_id = (
  SELECT id FROM users WHERE role_id='role_admin' ORDER BY created_at ASC LIMIT 1
)
WHERE owner_user_id IS NULL;

ALTER TABLE dns_zones
  ALTER COLUMN owner_user_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS ix_dns_zones_owner_user_id ON dns_zones(owner_user_id);

-- Associate mail domains with an owning panel user for RBAC scoping.
ALTER TABLE mail_domains
  ADD COLUMN IF NOT EXISTS owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL;

UPDATE mail_domains
SET owner_user_id = (
  SELECT id FROM users WHERE role_id='role_admin' ORDER BY created_at ASC LIMIT 1
)
WHERE owner_user_id IS NULL;

ALTER TABLE mail_domains
  ALTER COLUMN owner_user_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS ix_mail_domains_owner_user_id ON mail_domains(owner_user_id);

-- Job actor for UI scoping and audit ergonomics.
ALTER TABLE jobs
  ADD COLUMN IF NOT EXISTS actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS ix_jobs_actor_created_at ON jobs(actor_user_id, created_at);

COMMIT;

