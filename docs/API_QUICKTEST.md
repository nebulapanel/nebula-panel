# API Quick Test

Assumes API running at `http://127.0.0.1:8080`.

All provisioning operations are async:
- API returns a `job`
- `nebula-worker` executes the job via `nebula-agent`
- Poll `GET /v1/jobs/{id}` and `GET /v1/jobs/{id}/events`

## 1) Login

```bash
rm -f cookies.txt

LOGIN=$(curl -sS -c cookies.txt -X POST http://127.0.0.1:8080/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@localhost","password":"admin123!"}')

echo "$LOGIN" | jq

CSRF=$(echo "$LOGIN" | jq -r '.csrf_token')
```

Note: TOTP (Google Authenticator) is optional. If enabled for the account, login returns
`{"totp_required": true, "preauth_token": "..."}` and you must complete:

```bash
PREAUTH=$(echo "$LOGIN" | jq -r '.preauth_token')
TOTP=$(curl -sS -b cookies.txt -c cookies.txt -X POST http://127.0.0.1:8080/v1/auth/totp/verify \
  -H 'content-type: application/json' \
  -d "{\"preauth_token\":\"$PREAUTH\",\"code\":\"123456\"}")
CSRF=$(echo "$TOTP" | jq -r '.csrf_token')
```

## 2) Create user

```bash
USER_CREATE=$(curl -s -X POST http://127.0.0.1:8080/v1/users \
  -H "X-CSRF-Token: $CSRF" \
  -b cookies.txt \
  -H 'content-type: application/json' \
  -d '{"email":"user1@example.com","password":"StrongPass#1","role":"user"}')

echo "$USER_CREATE" | jq
USER_ID=$(echo "$USER_CREATE" | jq -r '.user.id')
JOB_ID=$(echo "$USER_CREATE" | jq -r '.job.id')
```

Wait for the Linux user + SFTP jail provisioning job to complete:

```bash
curl -s "http://127.0.0.1:8080/v1/jobs/$JOB_ID" \
  -H "X-CSRF-Token: $CSRF" \
  -b cookies.txt | jq

curl -s "http://127.0.0.1:8080/v1/jobs/$JOB_ID/events" \
  -H "X-CSRF-Token: $CSRF" \
  -b cookies.txt | jq
```

## 3) Create site

```bash
SITE_CREATE=$(curl -s -X POST http://127.0.0.1:8080/v1/sites \
  -H "X-CSRF-Token: $CSRF" \
  -b cookies.txt \
  -H 'content-type: application/json' \
  -d "{\"name\":\"My Site\",\"domain\":\"example.com\",\"owner_id\":\"$USER_ID\"}")

echo "$SITE_CREATE" | jq
SITE_ID=$(echo "$SITE_CREATE" | jq -r '.site.id')
SITE_JOB=$(echo "$SITE_CREATE" | jq -r '.job.id')
```

Wait for Nginx + PHP-FPM provisioning:

```bash
curl -s "http://127.0.0.1:8080/v1/jobs/$SITE_JOB" \
  -H "X-CSRF-Token: $CSRF" \
  -b cookies.txt | jq
```

## 5) Issue SSL for the site

```bash
SSL=$(curl -s -X POST "http://127.0.0.1:8080/v1/sites/$SITE_ID/ssl/issue" \
  -H "X-CSRF-Token: $CSRF" \
  -b cookies.txt \
  -H 'content-type: application/json' \
  -d '{}')

echo "$SSL" | jq
SSL_JOB=$(echo "$SSL" | jq -r '.job.id')
```

Poll:

```bash
curl -s "http://127.0.0.1:8080/v1/jobs/$SSL_JOB" \
  -H "X-CSRF-Token: $CSRF" \
  -b cookies.txt | jq
```
```
