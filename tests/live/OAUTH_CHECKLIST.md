# Manual OAuth checklist

Connect Google can't be automated against real Google: consent needs a person
in a browser. Run this list against a real OAuth client after changes to
`oauth.py`, `broker.py`, `service.py` or the samples, and before a release.
Record each pass in the results table at the bottom.

It needs the Google Cloud project and Sheets API from `SETUP.md` (steps 1 and 2).
Steps 9 and 10 also use the service-account key and test sheet from `SETUP.md`.

Where a step says "the management page", that's `/-/google-credentials` (ticket 14).
Until it lands, use the fallbacks given in each step.

## Before you start

Run everything from the main checkout (`just dev-otel` needs
`../datasette-otel-viewer` next to it). Start clean so earlier rows don't
confuse the checks:

```sh
just clean-dev
```

Put the OAuth client and a Fernet key in a file outside the repo (step 1 gives
you the client values):

```sh
# ~/.config/datasette-google-credentials/oauth-env
DATASETTE_GOOGLE_CREDENTIALS_KEY=...            # uv run datasette google-credentials generate-key
DATASETTE_GOOGLE_CREDENTIALS_CLIENT_ID=....apps.googleusercontent.com
DATASETTE_GOOGLE_CREDENTIALS_CLIENT_SECRET=...
```

Then start Datasette with that config, signed in as `root`:

```sh
set -a; . ~/.config/datasette-google-credentials/oauth-env; set +a
just dev-otel -c tests/live/oauth-dev.yml --root
```

Open the `http://127.0.0.1:8021/-/auth-token?token=...` URL it prints, but
change `127.0.0.1` to **`localhost`** first and use `localhost` throughout:
the redirect URI is built from the host you browse with, and it must match the
one registered with Google exactly.

Two views used by several steps (neither shows secrets):

```sh
# Stored credentials, from the internal DB
sqlite3 -header .tmp/internal.db "select id, type, label, google_subject, google_email, scopes, status, status_detail from datasette_google_credentials"
```

- `http://localhost:8021/-/google-credentials/api/credentials`: what the broker offers
  `root` (`CredentialInfo`: label, email, scopes, status).

## 1. Create an OAuth client

1. Get the redirect URI: the setup notice on the management page shows it, or
   `http://localhost:8021/-/google-credentials/api/status` returns it as
   `redirect_uri`. It should be
   `http://localhost:8021/-/google-credentials/oauth/callback`.
2. In the console, open **Google Auth Platform** →
   [**Clients**](https://console.cloud.google.com/auth/clients) →
   **Create client** (older consoles: **APIs & Services** → **Credentials** →
   **Create credentials** → **OAuth client ID**). If it asks you to configure
   the consent screen first, do step 2 and come back.
3. Application type **Web application**. Under **Authorized redirect URIs**
   add the URI from 1. No JavaScript origins are needed.
4. Create it, and copy the client ID and secret into the env file above.
   Restart `just dev-otel` after editing it.

- [ ] The client exists with exactly that redirect URI.

## 2. Choose Testing or Internal

In **Google Auth Platform** → [**Audience**](https://console.cloud.google.com/auth/audience)
(older consoles: **OAuth consent screen**):

- **External, Testing**: any Google account, but only the ones listed under
  **Test users**. Add yours. This is the status step 8 needs.
- **Internal**: Google Workspace only, every account in the organisation, no
  test-user list and no unverified-app warning. Refresh tokens don't get the
  7-day Testing expiry, so step 8 doesn't apply.

Under **Data access**, adding the scopes is optional: the connect URL requests
them either way. `openid email https://www.googleapis.com/auth/spreadsheets`
is the default set.

- [ ] Status recorded in the results table (Testing or Internal).

## 3. Connect, and check `sub`, email and scopes

1. Click **Connect Google** on the management page, or open
   `http://localhost:8021/-/google-credentials/connect?return_to=/-/google-credentials`.
2. Google shows the consent screen. With External/Testing it first warns
   "Google hasn't verified this app": **Continue**. Leave every box ticked and
   allow.
3. You land back on `return_to`.

- [ ] One row, `type = google_oauth`, `status = ok`.
- [ ] `google_subject` is Google's numeric account ID (about 21 digits), not
      the email.
- [ ] `google_email` is the account you picked, and the label defaults to it.
- [ ] `scopes` holds `openid`, `https://www.googleapis.com/auth/userinfo.email`
      (Google's name for `email`) and `https://www.googleapis.com/auth/spreadsheets`.
      Write down exactly what Google returned: the mock should match it.
- [ ] `/-/google-credentials/api/credentials` lists it for `root`.

## 4. Untick a scope during consent

1. Connect again with the **same** Google account.
2. On the consent screen, untick **See, edit, create and delete all your
   Google Sheets spreadsheets** (granular consent), then continue.

- [ ] Still one row for that account (same `id`, updated in place: D9), now
      without the `spreadsheets` scope.
- [ ] The management page shows it as "limited access", with a way to connect
      again. (Before ticket 14: `scopes` in the API response lacks it.)
- [ ] The importer (`/-/google-sheets-import/tmp`) doesn't offer it in its
      credential picker (it asks for `spreadsheets.readonly`), and its Connect
      Google link comes back to the importer.
- [ ] Connect again with every box ticked: the row regains `spreadsheets`.

## 5. Revoke at Google, then use it

1. Import something with the credential (step 9's import) so a token is
   cached, and note that it worked.
2. At <https://myaccount.google.com/linkedapps>, find the app and
   **Remove all access**.
3. Use the credential again: run the same import.

- [ ] The import fails with a message asking you to reconnect, not a 500.
- [ ] The row is now `status = broken`, with a `status_detail`.
- [ ] The management page shows it as broken, with **Reconnect**.
- [ ] Record whether the *first* use after revoking already failed, or whether
      the cached access token kept working until it expired (restart
      `just dev-otel` to drop the cache, and try again, if it kept working).

## 6. Reconnect

1. Click **Reconnect** (or open the connect URL again), same account, all
   boxes ticked.

- [ ] Same row `id`, `status = ok`, `status_detail` empty.
- [ ] The step 5 import works again.

## 7. Disconnect, and check the revoke

1. Delete the credential from the management page. Before ticket 14, run this
   in the browser console on any `localhost:8021` page, with the row's `id`:

   ```js
   await (await fetch("/-/google-credentials/api/credentials/<id>/delete", {method: "POST"})).json()
   ```

- [ ] The result says `revoked: true` (the UI reports it) and the row is gone.
- [ ] At <https://myaccount.google.com/linkedapps> the app no longer has
      access (reload the page).

## 8. Refresh-token expiry after 7 days in Testing (wiki D4 `← verify`)

Only for an External app in **Testing** status. Connect (step 3), then leave
the credential alone for **more than 7 days**. Don't disconnect it.

1. After day 7, run an import with it.

- [ ] Google refuses the refresh (`invalid_grant`), the row becomes
      `status = broken`, and the UI asks you to reconnect.
- [ ] Record the connect date, the check date and what happened, so the
      README's Testing-status caveat (ticket 19) can cite it.

## 9. Importer and exporter samples

`just dev` and `just dev-otel` load both samples from `samples/`. Use the test
sheet from `SETUP.md`. The database is `tmp` (`.tmp/tmp.db`).

With the OAuth credential (steps 3 or 6):

- [ ] Import: `/-/google-sheets-import/tmp`, pick the credential, paste the
      test sheet's URL, import the first tab into a new table. The table's rows
      and columns match the sheet; numbers stay numbers, empty cells are NULL.
- [ ] Export to a **new** spreadsheet: from the new table's actions menu,
      **Export to Google Sheets** → new spreadsheet. It opens in your Drive
      with the same rows. Put `=1+1` in a cell of a table first and check it
      arrives as literal text (RAW input, D32).
- [ ] Add an `export` tab to the test sheet by hand, then export a query
      (`/tmp?sql=select ...` → actions menu) into the **existing** sheet, tab
      `export`, with **Replace**. Run it twice: the second run replaces rather
      than appends.

With the service account (add the `SETUP.md` key on the management page. Before
ticket 14: `uv run datasette create-token root --secret abc123`, then
`jq -n --rawfile k "$DATASETTE_GOOGLE_CREDENTIALS_LIVE_SA_KEY" '{key_json: $k}' | curl -s -X POST -H "Authorization: Bearer <token>" -H 'Content-Type: application/json' --data @- http://localhost:8021/-/google-credentials/api/service-accounts`):

- [ ] The add response names `share_with_email` (the key's `client_email`).
- [ ] Import the test sheet with it.
- [ ] Export into the test sheet's `export` tab. Choosing a new spreadsheet
      is refused for a service account, and the page says why (D28).
- [ ] Import from a sheet **not** shared with it: the error names the
      `client_email` to share with.

## 10. Telemetry (`just dev-otel`)

After steps 3 to 9, open `http://localhost:8021/-/otel`.

- [ ] Spans are there for each path exercised:
      `datasette_google_credentials.oauth.callback` with `.oauth.exchange` and
      `.oauth.userinfo` under it, `.token`, `.token.refresh` (OAuth),
      `.token.mint` (service account), `.request`, `.oauth.revoke` (step 7).
- [ ] Metrics: `datasette_google_credentials.google.duration`, `.token_cache.lookups`,
      `.request.duration`, `.oauth.callbacks`, `.credentials.broken` (step 5).
- [ ] `.request` spans carry the host (`sheets.googleapis.com`), never a path
      or spreadsheet ID. No span or metric carries an email, actor id, token or
      key id (D29).
- [ ] A crude leak check on the stored telemetry prints `0` three times
      (your email, access-token prefix, refresh-token prefix):

      ```sh
      for s in "you@example.com" "ya29." "1//"; do grep -a -c -F "$s" .tmp/otel.db; done
      ```

## Results

One row per pass. Fill in each step's result: `pass`, `fail` (with a note),
`skipped` (with the reason), or `n/a`. Note anything where Google behaved
differently from the mock, and fix the mock.

Status: Testing or Internal (step 2). Live suite: the `just test-live` summary
line from the same day.

| Date | Who | Status | `just test-live` | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | | | | | | |
| | | | | | | | | | | | | | | |
