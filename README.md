# Hunar Vikas authentication service

See the repository [README](../README.md) for the complete local development
and deployment workflow.

Implements the auth side of `AUTH_HANDOFF_CONTRACT.md` v1.0 (email + password, verified sessions, employer approval).
Status: **authentication service implemented and tested against the current feature-app adapter.**

## Setup
```
pip install -r requirements.txt
cp .env.example .env            # fill AUTH_SECRET_KEY and Resend values (never commit .env)
python -m auth_service.cli init-db
python -m auth_service.cli seed-synthetic     # dev/test only: 3 synthetic accounts, passwords printed once
python -m pytest                              # 32 tests
```
Tested with: Python 3.12, Flask 3.1.3, SQLAlchemy 2.1.5, argon2-cffi 25.1.0. SQLite is used locally; PostgreSQL via Supabase is supported through `psycopg`.

Start the local server from `backend/`:
```
flask --app wsgi run --debug
```
From the repository root, use:
```
flask --app backend.wsgi run --debug
```

## Wiring into the feature app (`DEV_MODE=False`)
```python
from backend.app import create_app
from auth_service import AuthService

auth = AuthService.from_env()
app = create_app({"DEV_MODE": False}, identity_resolver=auth.resolve_identity)
auth.init_app(app)     # mounts /api/auth/*, the origin+CSRF guard and JSON error handling
```
Behind a reverse proxy, apply `werkzeug.middleware.proxy_fix.ProxyFix` so rate limiting sees the real client IP. The WSGI entry point is `backend.wsgi:app`.

## Resend email OTP delivery

The mailer can send OTP and password-reset messages through the
[Resend](https://resend.com/) HTTP API:

1. Verify the sender address or domain in Resend.
2. Create a Resend API key with permission to send email.
3. Set these variables in `.env` or the deployment secret store:

```text
AUTH_MAIL_BACKEND=resend
AUTH_MAIL_FROM=Hunar Vikas India <the-verified-sender@example.com>
AUTH_RESEND_API_KEY=re_your_secret_key
AUTH_RESEND_API_URL=https://api.resend.com/emails
```

Keep `AUTH_RESEND_API_KEY` only in deployment secrets or `.env`; never commit it.
Production startup fails if the Resend key is missing. The existing `file`
backend remains available for local development and tests.

## Decisions (contract section 9, items 3 and 4)
| Topic | Choice |
| --- | --- |
| Login method | Email + password (argon2id). Email ownership verified by a 6-digit code (10 min, 5 attempts) **or** a single-use link token. Signup never logs in; verification does. |
| Roles | `individual`, `employer` only. Frontend mapping: Citizen/Artisan -> `individual`; Employer -> `employer`; Training Partner is not supported by this contract. |
| Resolver id | `hv:user:<uuid4 hex>`, immutable. Deleted accounts stay as tombstones so ids are never reused. `member_code` (`HVI-XXXX-XXXX-C`, same algorithm as the frontend) is display-only. |
| Session | Server-side row, cookie holds a random 256-bit value (only its SHA-256 is stored). `HttpOnly`, `SameSite=Lax`, `Path=/`, `Secure` + `__Host-` prefix when `AUTH_COOKIE_SECURE=true`. |
| Lifetimes | Default: 12 h absolute / 2 h idle, browser-session cookie. "Keep me signed in": 30 d absolute / 14 d idle. |
| Rotation / revocation | New session id on every login. Logout revokes the current session; `logout-all`, password reset, suspension and deletion revoke all. |
| CSRF | Per-session token = HMAC(secret, session). Returned by login/verify/`GET /api/auth/me`; every state-changing request with a session cookie (feature routes **and** logout) must send `X-CSRF-Token`. Origin must match the host. |
| Recovery | Email link (30 min, single use, token in the URL fragment). Resets revoke every session. |
| Rate limits | DB-backed, HMAC-keyed (no raw IPs/emails stored): login 10 failures/15 min per email and 50 per IP; register 5/h per email, 10/h per IP; verify, resend, forgot, reset limited too. |
| Employer approval | Operator CLI + `AUTH_OPERATOR_IDS` allow-list; every action in `audit_log`. Approval is checked on **every request** (membership + organisation + account status). |
| Not done (pending joint work) | User-facing account deletion endpoint, unpublishing jobs when approval is revoked, change-password-while-signed-in, retention policy. |

## Routes (all JSON; every POST, including logout, must send `Content-Type: application/json`, body `{}` if empty)
| Method | Route | Notes |
| --- | --- | --- |
| POST | `/api/auth/register` | `{email, password, display_name?, account_type, organization_name?, accept_terms:true}` -> 202 `{verification_required:true}` (identical for existing emails) |
| POST | `/api/auth/verify-email` | `{email, otp}` or `{token}`, optional `remember` -> 200 session payload + cookie |
| POST | `/api/auth/resend-verification` | `{email}` -> 202 always |
| POST | `/api/auth/login` | `{email, password, remember?}` -> 200 payload + cookie; 401 generic; 403 `email_not_verified` / `account_unavailable`; 429 |
| POST | `/api/auth/logout`, `/api/auth/logout-all` | needs `X-CSRF-Token` |
| GET | `/api/auth/me` | `{authenticated:false}` or `{authenticated:true, user:{member_code, display_name, email, role, approved, approval_status, organization}, csrf_token}` |
| POST | `/api/auth/forgot-password` | `{email}` -> 202 always |
| POST | `/api/auth/reset-password` | `{token, new_password}` -> 200; clears cookie |

Errors: `{"error": "<message>", "code": "<machine code>", "fields": {...}?}` (compatible with the feature app's `{"error": ...}`).

## Frontend wiring
The login, registration, and dashboard apps now use the shared
`shared/auth.ts` client. It sends JSON requests with
`credentials: 'include'`, stores only the server-provided CSRF token in
memory, and never stores passwords or sessions in localStorage. Registration
posts the account type and employer organisation, then verifies the emailed
6-digit code before opening the dashboard. The dashboard loads `/api/auth/me`
and redirects unauthenticated users to `/login/`.

Set `VITE_API_BASE_URL` only when the API is exposed through a trusted reverse
proxy; leave it empty when the frontend and API share an origin. In
production, serve the static apps and Flask API behind the same HTTPS origin so
the `__Host-hv_session` cookie and same-origin CSRF policy work as designed.

For production, run the WSGI application with Gunicorn rather than Flask's
development server:

```
gunicorn --bind 0.0.0.0:$PORT wsgi:app
```

Put the frontend and this WSGI service behind one HTTPS origin (for example,
an edge reverse proxy routing `/api/*` to the backend). Do not expose the API
on a separate browser origin without also redesigning the cookie and origin
policy.

### Supabase PostgreSQL

Install the dependencies from `requirements.txt` and set the Supabase
connection string as the server-side `AUTH_DATABASE_URL` secret:

```text
postgresql+psycopg://postgres:<password>@<supabase-host>:5432/postgres?sslmode=require
```

Use Supabase's **Session Pooler** connection string when deploying multiple
workers. Never put this value in frontend environment variables. Run the
one-time schema initialization from the backend service:

```bash
python -m auth_service.cli init-db
```

The WSGI entry point also calls `create_all()` during startup for the initial
deployment, but use versioned migrations before future schema changes.

## Operator commands
`python -m auth_service.cli pending | approve|reject|revoke <org-id|owner-email> --reviewer ID --reason "..." | suspend|reactivate|delete <email> --reviewer ID`

## Known limits
- Test/development file mail goes to `instance/outbox/*.eml` (contains codes; git-ignored). Production requires authenticated Resend or SMTP (enforced).
- Login lockout per email can be abused to lock a victim out for 15 minutes; chosen over account takeover risk.
- Emails still show "not recorded" for IP/location because the frontend template has those fields; consider removing them from the template.
- `create_all` creates tables; add Alembic migrations before the first schema change after launch.
