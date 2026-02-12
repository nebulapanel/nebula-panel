BEGIN;

-- Panel user -> Linux user mapping for real tenancy (SFTP + filesystem isolation).
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS linux_username TEXT,
  ADD COLUMN IF NOT EXISTS sftp_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN IF NOT EXISTS sftp_password_enc TEXT,
  ADD COLUMN IF NOT EXISTS sftp_password_hash TEXT;

-- Backfill deterministic usernames for existing rows.
UPDATE users
SET linux_username = COALESCE(
  NULLIF(linux_username, ''),
  'nebula_' || substring(
    regexp_replace(lower(replace(id, 'user_', '')), '[^a-z0-9]', '', 'g'),
    1,
    8
  )
)
WHERE linux_username IS NULL OR linux_username = '';

CREATE UNIQUE INDEX IF NOT EXISTS ux_users_linux_username ON users(linux_username);

ALTER TABLE users
  ALTER COLUMN linux_username SET NOT NULL;

-- Fix existing site root paths (older versions used owner_user_id directly as a path segment).
UPDATE sites s
SET root_path = '/home/' || u.linux_username || '/web/' || s.primary_domain || '/public_html'
FROM users u
WHERE u.id = s.owner_user_id;

COMMIT;

