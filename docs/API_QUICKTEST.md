# API Quick Test

Assumes API running at `http://127.0.0.1:8080`.

## 1) Login

```bash
LOGIN=$(curl -si -X POST http://127.0.0.1:8080/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@localhost","password":"admin123!"}')

COOKIE=$(echo "$LOGIN" | awk '/set-cookie: nebula_csrf/ {print $2}' | tr -d ';\r')
CSRF=$(echo "$LOGIN" | sed -n '/^\r$/,$p' | jq -r '.csrf_token')
PREAUTH=$(echo "$LOGIN" | sed -n '/^\r$/,$p' | jq -r '.preauth_token')
```

## 2) TOTP verify

```bash
SESSION=$(curl -s -X POST http://127.0.0.1:8080/v1/auth/totp/verify \
  -H 'content-type: application/json' \
  -d "{\"preauth_token\":\"$PREAUTH\",\"code\":\"000000\"}" | jq -r '.session.token')
```

## 3) Create user

```bash
curl -s -X POST http://127.0.0.1:8080/v1/users \
  -H "Authorization: Bearer $SESSION" \
  -H "X-CSRF-Token: $CSRF" \
  -H "Cookie: $COOKIE" \
  -H 'content-type: application/json' \
  -d '{"email":"user1@example.com","password":"StrongPass#1","role":"user"}' | jq
```
