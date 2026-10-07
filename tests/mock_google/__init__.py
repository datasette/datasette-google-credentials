"""In-process mock of the Google endpoints datasette-google-credentials talks to.

Served by FastAPI and mounted with ``httpx2.ASGITransport`` (see
``tests/fixtures_google.py``): no uvicorn, no ports, no network.

Modelled on the sqlite-google-sheets mock (``tests/mock_google/`` at commit
6413af08bfecd39ed539fd8cfb5ba9df0c872235), which has the JWT-bearer token
endpoint, Google-shaped errors, fault injection and a Sheets read API but no
authorization-code flow, PKCE, revoke or userinfo. This package is an
independent implementation of the same ideas, not a copy of that code.

Modules:
    keys.py         RSA service-account keys and the id_token signing key,
                    generated per test session (no private keys committed)
    tokens.py       access-token store, JWT-bearer grant (service accounts)
    oauth.py        authorization code + PKCE, refresh, revoke, userinfo
    faults.py       injected failures ("the next POST /revoke returns 500")
    sheets.py       minimal Sheets v4: spreadsheet get, values get / update /
                    append / clear, spreadsheet create
    errors.py       Google-shaped error bodies
    app.py          the FastAPI app and the request log
"""

# The OAuth endpoints live at http://mock-google/... (the plugin's
# google_base_urls point there). Sheets has no base URL in the plugin config,
# so consumers use the real one; the ASGI transport routes it here anyway.
MOCK_HOST = "mock-google"
MOCK_BASE = f"http://{MOCK_HOST}"
SHEETS_HOST = "sheets.googleapis.com"
SHEETS_BASE = f"https://{SHEETS_HOST}"
