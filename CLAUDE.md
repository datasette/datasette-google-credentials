# datasette-google-auth

Google credentials for Datasette. Stores service-account keys (shared through
datasette-acl) and per-user OAuth connections (owner-only), encrypted at rest,
and hands out access tokens to other plugins through a Python broker API.
Nothing is exposed in SQL. Importer and exporter samples in `samples/` prove the API.

## Local-only planning files

- `wiki/` and `todos/` are local notes, excluded via `.git/info/exclude`. Never
  commit them or add them to `.gitignore`.
- **Decisions are binding and live in `wiki/01-decisions.md` (D1–D18).** Read it
  before starting work. If a ticket conflicts with it, the decisions file wins.
  Record new decisions there and follow-ups in `wiki/90-future-ideas.md`.
- Tickets for v0 are in `todos/v0/` (index and shared context in `todos/v0/README.md`).

## Architecture

- **Backend:** Python, Datasette >=1.0a41, datasette-plugin-router, Pydantic
- **Auth deps:** PyJWT[crypto] (RS256 service-account JWTs), cryptography (Fernet),
  httpx2 (token exchange, refresh, `cred.request()`). No google-auth, no requests.
- **Permissions:** datasette-acl is a hard dependency; datasette-acl-share provides
  the share dialog for service accounts
- **Frontend:** Svelte 5 (runes), TypeScript, Vite, openapi-fetch (arrives in ticket 13)
- **Database:** sqlite-migrate for internal.db schema management (ticket 03)
- **Build:** Just (Justfile), uv (Python), npm (frontend)

`../datasette-acl` and `../datasette-acl-share` are editable path sources (see
`[tool.uv.sources]`). datasette-acl must be on a branch with the
`datasette_acl.grants` Principal API (`main` or `grant-event`).

## Commands

| Command | What it does |
|---------|-------------|
| `just dev` | Datasette dev server on port 8021, loads `samples/` via `--plugins-dir` |
| `just dev-with-hmr` | Datasette + Vite HMR (restarts on .py/.html changes) |
| `just frontend-dev` | Vite dev server on port 5182 (stub until ticket 13) |
| `just frontend` | Build frontend for production (stub until ticket 13) |
| `just types` | Regenerate TypeScript types from Python (stub until ticket 13) |
| `just format` | ruff fix + format |
| `just check` | ty + ruff lint + ruff format check |
| `just test` | Run Python tests (pytest, asyncio strict) |
| `just clean-dev` | Delete `.tmp/` (dev databases) |
| `uv run datasette google-auth generate-key` | Print a new Fernet key for `encryption-key` |
| `uv run datasette google-auth rotate-keys --internal X -c cfg.yml` | Re-encrypt every credential with the first key |

## Project Structure

```
datasette_google_auth/
├── __init__.py              # Plugin hooks + re-exports the public broker API (`__all__`)
├── broker.py                # list_credentials / get_credential / Credential.token() + .request()
├── cli.py                   # `datasette google-auth generate-key | rotate-keys`
├── config.py                # Pydantic plugin config, validated at startup
├── crypto.py                # SecretBox (Fernet/MultiFernet), encrypt/decrypt + lazy key rotation
├── errors.py                # GoogleAuthError + subclasses (stable `code`), error_response()
├── http.py                  # client(datasette): the only outbound httpx2 factory
├── internal_migrations.py   # sqlite-migrate: credentials table (append-only)
├── internal_db.py           # InternalDB + CredentialRow (never decrypts)
├── models.py                # CredentialInfo: the secret-free public view of a credential
├── oauth.py                 # Connect Google: PKCE + signed state flow, code exchange, refresh
├── permissions.py           # Actions, ServiceAccountResource, acl roles, can_* helpers
├── router.py                # Shared Router instance
├── service_account.py       # parse_key (ignores token_uri), mint_token, add / rotate SA keys
├── tokens.py                # Token(access_token, expires_at epoch secs, scopes); repr hides the token
├── token_cache.py           # TokenCache (in-memory, per-process, LRU) + get_token_cache(datasette)
└── routes/
    ├── pages.py             # Page routes (render HTML) + OAuth connect/callback redirects
    └── api.py               # API routes (return JSON)
samples/                     # Consumer sample plugins (importer, exporter)
tests/
├── conftest.py              # Imports shared fixtures; later tickets add theirs here
├── fixtures_google.py       # mock_google fixture, service_account_keys, network block
├── mock_google/             # In-process mock Google (OAuth, SA tokens, minimal Sheets)
├── test_broker.py
├── test_mock_google.py
├── test_oauth.py
├── test_config.py
├── test_crypto.py
├── test_internal_db.py
├── test_permissions.py
├── test_service_account.py
├── test_smoke.py
└── test_token_cache.py
```

Planned per the house layout (D18): `page_data.py`,
`templates/google_auth_base.html`, `frontend/`,
`scripts/typegen-pagedata.py`. Update this file as they land.

## Routes

- `GET /-/google-auth/connect?return_to=/...` → start OAuth connect (404 without
  `client_id`/`client_secret`, 403 without `google-auth-connect`)
- `GET /-/google-auth/oauth/callback` → OAuth redirect URI

Planned (D13):
- `GET /-/google-auth` → management page
- `GET /-/google-auth/api/credentials?scopes=...` → mirrors `list_credentials()`

## Hooks Used

- `register_routes()` — registers all routes from the shared router
- `register_actions()` — three global actions (`google-auth-connect`,
  `google-auth-add-service-account`, `google-auth-admin`) and three per-SA
  actions (`google-service-account-use` / `-edit` / `-manage`)
- `datasette_acl_roles()` — User / Editor / Manager for `google-service-account`
- `register_commands()` — adds the `datasette google-auth` CLI group (`cli.py`)
- `startup()` — validates plugin config and Fernet key format (bad config → `StartupError`), creates the per-process token cache, then applies internal-DB migrations

## Environment Variables

- `DATASETTE_SECRET` — required for the dev server (`just dev` sets it)
- `DATASETTE_GOOGLE_AUTH_KEY` — Fernet encryption key, usually wired as
  `encryption-key: {"$env": "DATASETTE_GOOGLE_AUTH_KEY"}` (ticket 04)

## Invariants

- Never call `datasette.allowed()` for an OAuth credential: access is
  `owner_id == actor.id`, hard-coded.
- `get_credential()` always re-reads the row and re-checks access before
  consulting the token cache, and so does every `Credential.token()` /
  `.request()`, so a held `Credential` never outlives a revocation.
- No secrets, tokens or key material in responses, logs, events, errors or telemetry.
- Google URLs come only from config. Never honour a key file's `token_uri`.
- The default test suite never contacts real Google; use the `mock_google`
  fixture (`tests/fixtures_google.py`). Internet sockets and DNS are blocked
  for the whole suite.

## Key Conventions

- **`__init__.py` is hooks only** (plus re-exports of the public API). Logic goes in its own module.
- **`datasette.allowed(...)` is keyword-only.**
- **httpx2, not httpx.**
- **Svelte 5 runes**: `$state()`, `$derived()`, `$effect()`, `$props()`
- **IDs**: `python-ulid`
- **Internal DB reads**: use `execute_write_fn()` even for reads
- **Secrets**: encrypt with `crypto.encrypt_secret()` and read with
  `crypto.decrypt_credential()` (lazily re-encrypts rows under an old key). Both
  raise `EncryptionNotConfigured` without a key; never write a secret any other way.
- **Template**: one template for all pages; routes vary `entrypoint` and `page_data`
