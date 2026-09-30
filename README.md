# datasette-google-auth

Google credentials for Datasette: shared service accounts and per-user OAuth
connections, stored encrypted and brokered to other plugins.

**Work in progress.** Setup, security model and the consumer API are not
documented yet.

## Development

```bash
uv sync
just test
just check
just dev
```

`uv sync` expects sibling checkouts of `datasette-acl` and `datasette-acl-share`
in `../` (see `[tool.uv.sources]` in `pyproject.toml`).

## Telemetry

OpenTelemetry spans and metrics under the `datasette_google_auth` scope, using
Datasette's telemetry kit. Nothing is recorded unless you install an
OpenTelemetry SDK and provider. The reference below is generated from
`datasette_google_auth/telemetry_registry.py` by `just telemetry-doc`; don't
edit it by hand.

<!-- telemetry-reference:start -->

#### Spans

**`datasette_google_auth.token`** — `Credential.token()`: re-reading the credential, re-checking access, then serving from the token cache or minting/refreshing. On a cache miss the `token.mint` or `token.refresh` span is its child. Status is `ERROR` for any exception except the access decisions `CredentialNotFound`, `CredentialForbidden` and `MissingScopes`, which are outcomes (like an HTTP 4xx) and only set `error.type`.

Attributes:

- `datasette_google_auth.credential.id` — The credential's ULID. Opaque, and **spans only, never a metric dimension**. Owner, actor and email are never recorded.
- `datasette_google_auth.credential.type` *(optional)* — `service_account` or `google_oauth`. Set once the credential has been re-read; absent when it doesn't exist or the actor can't see it.
- `datasette_google_auth.cache` *(optional)* — `hit` or `miss`. Set once the token is in hand; absent when access was denied or the fetch failed.
- `error.type` *(optional)* — Class name of the exception that ended the operation. Never the message.

**`datasette_google_auth.request`** — `Credential.request()`: one authenticated call to a Google API, with its `token` span(s) as children (two on a 401 retry). A returned 4xx or 5xx is the consumer's to handle and leaves the status unset; status is `ERROR` only when an exception escapes, other than the access decisions the `token` span also exempts.

Attributes:

- `datasette_google_auth.credential.id` — The credential's ULID. Opaque, and **spans only, never a metric dimension**. Owner, actor and email are never recorded.
- `datasette_google_auth.credential.type` — `service_account` or `google_oauth`.
- `http.request.method` — The request method, clamped by core's `clamp_http_method` (anything outside RFC 9110 + PATCH is `_OTHER`).
- `server.address` — The host of the requested URL. Never the path or query.
- `http.response.status_code` *(optional)* — The HTTP status of the API's reply: the retry's, after a 401. Absent when no response arrived.
- `datasette_google_auth.retried` — `True` if the first response was a 401, so the cached token was evicted and the request retried once with a fresh one.
- `error.type` *(optional)* — Class name of the exception that ended the operation. Never the message.

**`datasette_google_auth.token.mint`** — A service-account JWT-bearer exchange at Google's token endpoint, for the broker or the live test when a key is added or rotated. Status is `ERROR` (with no description) whenever `outcome` isn't `ok`.

Attributes:

- `datasette_google_auth.scopes.count` — How many scopes the service-account token was minted for.
- `datasette_google_auth.outcome` — How the Google call ended: `ok`; `invalid_grant` (key deleted or disabled, grant revoked, code reused); `http_error` (any other non-200); `network_error` (Google never answered); `invalid_response` (a 200 without the expected fields).
- `http.response.status_code` *(optional)* — The HTTP status of Google's reply. Absent when Google never answered.
- `datasette_google_auth.google.error` *(optional)* — Google's OAuth `error` code, from a failed reply or the callback's `error` parameter. Clamped to the RFC 6749 / RFC 7009 codes plus Google's documented ones; anything else is `_OTHER`. Never the `error_description`.
- `error.type` *(optional)* — Class name of the exception that ended the operation. Never the message.

**`datasette_google_auth.token.refresh`** — An OAuth refresh-token grant at Google's token endpoint. Status is `ERROR` (with no description) whenever `outcome` isn't `ok`.

Attributes:

- `datasette_google_auth.outcome` — How the Google call ended: `ok`; `invalid_grant` (key deleted or disabled, grant revoked, code reused); `http_error` (any other non-200); `network_error` (Google never answered); `invalid_response` (a 200 without the expected fields).
- `http.response.status_code` *(optional)* — The HTTP status of Google's reply. Absent when Google never answered.
- `datasette_google_auth.google.error` *(optional)* — Google's OAuth `error` code, from a failed reply or the callback's `error` parameter. Clamped to the RFC 6749 / RFC 7009 codes plus Google's documented ones; anything else is `_OTHER`. Never the `error_description`.
- `datasette_google_auth.refresh_token.rotated` *(optional)* — `True` if Google returned a new refresh token. Set on success only.
- `error.type` *(optional)* — Class name of the exception that ended the operation. Never the message.

**`datasette_google_auth.oauth.exchange`** — The authorization-code (+ PKCE verifier) exchange during the Connect Google callback. Status is `ERROR` (with no description) whenever `outcome` isn't `ok`.

Attributes:

- `datasette_google_auth.outcome` — How the Google call ended: `ok`; `invalid_grant` (key deleted or disabled, grant revoked, code reused); `http_error` (any other non-200); `network_error` (Google never answered); `invalid_response` (a 200 without the expected fields).
- `http.response.status_code` *(optional)* — The HTTP status of Google's reply. Absent when Google never answered.
- `datasette_google_auth.google.error` *(optional)* — Google's OAuth `error` code, from a failed reply or the callback's `error` parameter. Clamped to the RFC 6749 / RFC 7009 codes plus Google's documented ones; anything else is `_OTHER`. Never the `error_description`.
- `error.type` *(optional)* — Class name of the exception that ended the operation. Never the message.

**`datasette_google_auth.oauth.userinfo`** — The OpenID userinfo call that identifies the Google account during the Connect Google callback. Status is `ERROR` (with no description) whenever `outcome` isn't `ok`.

Attributes:

- `datasette_google_auth.outcome` — How the Google call ended: `ok`; `invalid_grant` (key deleted or disabled, grant revoked, code reused); `http_error` (any other non-200); `network_error` (Google never answered); `invalid_response` (a 200 without the expected fields).
- `http.response.status_code` *(optional)* — The HTTP status of Google's reply. Absent when Google never answered.
- `datasette_google_auth.google.error` *(optional)* — Google's OAuth `error` code, from a failed reply or the callback's `error` parameter. Clamped to the RFC 6749 / RFC 7009 codes plus Google's documented ones; anything else is `_OTHER`. Never the `error_description`.
- `error.type` *(optional)* — Class name of the exception that ended the operation. Never the message.

**`datasette_google_auth.oauth.revoke`** — Best-effort revocation of a refresh token when an OAuth credential is deleted. The delete goes ahead either way. Status is `ERROR` (with no description) whenever `outcome` isn't `ok`.

Attributes:

- `datasette_google_auth.outcome` — How the Google call ended: `ok`; `invalid_grant` (key deleted or disabled, grant revoked, code reused); `http_error` (any other non-200); `network_error` (Google never answered); `invalid_response` (a 200 without the expected fields).
- `http.response.status_code` *(optional)* — The HTTP status of Google's reply. Absent when Google never answered.
- `datasette_google_auth.google.error` *(optional)* — Google's OAuth `error` code, from a failed reply or the callback's `error` parameter. Clamped to the RFC 6749 / RFC 7009 codes plus Google's documented ones; anything else is `_OTHER`. Never the `error_description`.
- `error.type` *(optional)* — Class name of the exception that ended the operation. Never the message.

**`datasette_google_auth.oauth.callback`** — The Connect Google callback (`GET /-/google-auth/oauth/callback`) once the actor is allowed to connect, child of core's request span, with the `oauth.exchange` and `oauth.userinfo` spans as children. Status is `ERROR` for `google_error`, `no_refresh_token`, `invalid_grant`, `token_error`, `not_configured` or an unexpected exception; a user cancelling or a stale link is not an error.

Attributes:

- `datasette_google_auth.callback.result` — How the Connect Google callback ended: `created` / `reconnected` (success); `cancelled` (the user clicked Cancel); `google_error` (Google sent another `error`); `invalid_state` (bad, expired or foreign state or flow cookie); `no_code`; `no_refresh_token`; `invalid_grant` (the code exchange was refused); `token_error` (any other Google failure); `not_configured` (no `encryption-key`). Absent only when an unexpected exception escaped.
- `datasette_google_auth.credential.id` *(optional)* — The ULID of the credential created or reconnected. Set on success only.
- `datasette_google_auth.google.error` *(optional)* — Google's OAuth `error` code, from a failed reply or the callback's `error` parameter. Clamped to the RFC 6749 / RFC 7009 codes plus Google's documented ones; anything else is `_OTHER`. Never the `error_description`.
- `datasette_google_auth.scopes.missing` *(optional)* — How many configured API scopes the user didn't grant (partial consent). Set on success only; `0` when everything was granted.
- `error.type` *(optional)* — Class name of the exception that ended the operation. Never the message.

#### Metrics

| Metric | Kind | Unit | Attributes | Description |
|---|---|---|---|---|
| `datasette_google_auth.google.duration` | Histogram | `s` | `datasette_google_auth.google.operation`<br>`datasette_google_auth.outcome`<br>`datasette_google_auth.google.error` | Duration of one call to a Google OAuth endpoint, by operation and outcome. Its counts are the token fetches by type and outcome: `operation=mint` is service accounts (live tests of new keys included), `operation=refresh` is OAuth. |
| `datasette_google_auth.token_cache.lookups` | Counter | `{lookup}` | `datasette_google_auth.credential.type`<br>`datasette_google_auth.cache` | Token-cache lookups by credential type and `hit` / `miss`. Hit ratio is hits over the total. |
| `datasette_google_auth.request.duration` | Histogram | `s` | `datasette_google_auth.credential.type`<br>`http.request.method`<br>`http.response.status_code`<br>`datasette_google_auth.retried`<br>`error.type` | Duration of `Credential.request()`, token fetches and a 401 retry included. |
| `datasette_google_auth.credentials.broken` | Counter | `{credential}` | `datasette_google_auth.credential.type` | Credentials marked broken because Google refused them (`invalid_grant`). Counted only when the compare-and-swap lands, so a race with a reconnect or rotation isn't counted. |
| `datasette_google_auth.oauth.callbacks` | Counter | `{callback}` | `datasette_google_auth.callback.result` | Connect Google callbacks by result. |

Attribute meanings match the span attributes of the same name above. `datasette_google_auth.credential.id` is never a metric dimension, and no signal carries a token, code, key material, email, actor id, label, URL path or query, or error message.

Histogram buckets (seconds):

- `datasette_google_auth.google.duration`: 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
- `datasette_google_auth.request.duration`: 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10

<!-- telemetry-reference:end -->
