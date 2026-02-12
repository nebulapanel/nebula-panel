# API Quick Test

Assumes API running at `http://127.0.0.1:8080`.

All provisioning operations are async:
- API returns a `job`
- `nebula-worker` executes the job via `nebula-agent`
- Poll `GET /v1/jobs/{id}` and `GET /v1/jobs/{id}/events`

## 1) Login

```bash
LOGIN=$(curl -si -X POST http://127.0.0.1:8080/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@localhost","password":"admin123!"}')

PREAUTH=$(echo "$LOGIN" | sed -n '/^\r$/,$p' | jq -r '.preauth_token')
```

## 2) TOTP verify

```bash
TOTP=$(curl -si -X POST http://127.0.0.1:8080/v1/auth/totp/verify \
  -H 'content-type: application/json' \
  -d "{\"preauth_token\":\"$PREAUTH\",\"code\":\"000000\"}")

SESSION=$(echo "$TOTP" | sed -n '/^\r$/,$p' | jq -r '.session.token')
CSRF=$(echo "$TOTP" | sed -n '/^\r$/,$p' | jq -r '.csrf_token')
COOKIE=$(echo "$TOTP" | awk '/set-cookie: nebula_csrf/ {print $2}' | tr -d ';\r')
```

## 3) Create user

```bash
USER_CREATE=$(curl -s -X POST http://127.0.0.1:8080/v1/users \
  -H "Authorization: Bearer $SESSION" \
  -H "X-CSRF-Token: $CSRF" \
  -H "Cookie: $COOKIE" \
  -H 'content-type: application/json' \
  -d '{"email":"user1@example.com","password":"StrongPass#1","role":"user"}')

echo "$USER_CREATE" | jq
USER_ID=$(echo "$USER_CREATE" | jq -r '.user.id')
JOB_ID=$(echo "$USER_CREATE" | jq -r '.job.id')
```

Wait for the Linux user + SFTP jail provisioning job to complete:

```bash
curl -s "http://127.0.0.1:8080/v1/jobs/$JOB_ID" \
  -H "Authorization: Bearer $SESSION" \
  -H "X-CSRF-Token: $CSRF" \
  -H "Cookie: $COOKIE" | jq

curl -s "http://127.0.0.1:8080/v1/jobs/$JOB_ID/events" \
  -H "Authorization: Bearer $SESSION" \
  -H "X-CSRF-Token: $CSRF" \
  -H "Cookie: $COOKIE" | jq
```

## 4) Create site

```bash
SITE_CREATE=$(curl -s -X POST http://127.0.0.1:8080/v1/sites \
  -H "Authorization: Bearer $SESSION" \
  -H "X-CSRF-Token: $CSRF" \
  -H "Cookie: $COOKIE" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"My Site\",\"domain\":\"example.com\",\"owner_id\":\"$USER_ID\"}")

echo "$SITE_CREATE" | jq
SITE_ID=$(echo "$SITE_CREATE" | jq -r '.site.id')
SITE_JOB=$(echo "$SITE_CREATE" | jq -r '.job.id')
```

Wait for Nginx + PHP-FPM provisioning:

```bash
curl -s "http://127.0.0.1:8080/v1/jobs/$SITE_JOB" \
  -H "Authorization: Bearer $SESSION" \
  -H "X-CSRF-Token: $CSRF" \
  -H "Cookie: $COOKIE" | jq
```

## 5) Issue SSL for the site

```bash
SSL=$(curl -s -X POST "http://127.0.0.1:8080/v1/sites/$SITE_ID/ssl/issue" \
  -H "Authorization: Bearer $SESSION" \
  -H "X-CSRF-Token: $CSRF" \
  -H "Cookie: $COOKIE" \
  -H 'content-type: application/json' \
  -d '{}')

echo "$SSL" | jq
SSL_JOB=$(echo "$SSL" | jq -r '.job.id')
```

Poll:

```bash
curl -s "http://127.0.0.1:8080/v1/jobs/$SSL_JOB" \
  -H "Authorization: Bearer $SESSION" \
  -H "X-CSRF-Token: $CSRF" \
  -H "Cookie: $COOKIE" | jq
```
```
