# Live tests (`just test-live`)

The rest of the suite runs against the in-process mock in `tests/mock_google/`,
with every internet socket blocked. The mock can drift from real Google (wiki
D17), so this directory holds two checks against the real thing:

- `test_live.py`: automated, service account only. Run with `just test-live`.
- `OAUTH_CHECKLIST.md`: a manual pass over Connect Google, which needs a browser
  and a person to click through consent.

Both are opt-in. `just test` never collects `tests/live/` (`norecursedirs` in
`pyproject.toml`), CI never runs it, and `just test-live` skips everything,
saying which variable is missing, until the environment below is set.

## What the automated tests cover

Every call goes through the public API with the plugin's default Google URLs and
no injected transport:

| Test | Checks |
|---|---|
| `test_add_service_account_does_live_exchange` | `add_service_account` does its pre-save token exchange at `oauth2.googleapis.com` and stores the credential, labelled with `client_email` |
| `test_key_google_rejects_is_not_saved` | the same key with a private key Google never issued: Google's `invalid_grant` becomes `InvalidServiceAccountKey`, nothing is saved, no key text in the message |
| `test_read_values` | `get_credential(scopes=[spreadsheets.readonly])` then `Credential.request()`: spreadsheet metadata and `values.get` on the first tab |
| `test_write_and_read_back_in_scratch_tab` | `spreadsheets` scope: add the `datasette-google-auth live` tab if missing, clear it, `values:append` with RAW input, read it back; `=1+1` stays literal text |
| `test_delete_credential` | `service.delete()` names the key to delete in the Cloud console, evicts the token cache, and a held `Credential` then raises `CredentialNotFound` |
| `test_bogus_token_uri_still_exchanges_at_google` | a key whose `token_uri` is `https://token-uri.invalid/token` still exchanges at `oauth2.googleapis.com`; a recording transport shows that only Google hosts were contacted |

A run makes about 20 requests to Google, well inside the Sheets API's quota of
60 reads per minute per user. Don't loop the suite.

## Environment

| Variable | What |
|---|---|
| `DATASETTE_GOOGLE_AUTH_LIVE_SA_KEY` | **Path** to a service-account JSON key file. The key is read from that file, never from the environment, and never printed. |
| `DATASETTE_GOOGLE_AUTH_LIVE_SHEET` | URL or ID of a throwaway spreadsheet shared with the key's `client_email` as **Editor** |

Keep both in a file outside the repo and `source` it; never commit them:

```sh
# ~/.config/datasette-google-auth/live-test-env
DATASETTE_GOOGLE_AUTH_LIVE_SA_KEY=$HOME/.config/datasette-google-auth/live-sa-key.json
DATASETTE_GOOGLE_AUTH_LIVE_SHEET=https://docs.google.com/spreadsheets/d/<id>/edit
```

```sh
set -a; . ~/.config/datasette-google-auth/live-test-env; set +a
just test-live           # -rs --tb=short; extra flags pass through, e.g. just test-live -k read
```

Run the live tests on their own. The default suite's network block is
session-scoped, so a mixed run (`pytest tests tests/live`) fails the live tests
at setup with a message saying so.

## One-time Google setup

You need a Google account and a Google Cloud project. Nothing here needs
billing.

### 1. Create a Google Cloud project

1. Open <https://console.cloud.google.com/projectcreate>.
2. Name it (for example `datasette-google-auth-live`) and create it. Make sure
   it's the selected project in the console header for the steps below.

### 2. Enable the Google Sheets API

1. Open <https://console.cloud.google.com/apis/library/sheets.googleapis.com>.
2. Click **Enable**.

That's the only API the tests and the samples call. The token, revoke and
userinfo endpoints need nothing enabled.

### 3. Create the service account and a key

1. Open <https://console.cloud.google.com/iam-admin/serviceaccounts> and click
   **Create service account**.
2. Name it (for example `live-tests`). Skip the optional role and user-access
   steps: it needs no IAM roles, only access to the one spreadsheet.
3. Open the new account, go to **Keys** → **Add key** → **Create new key** →
   **JSON**. The browser downloads the key file.
4. Move the file somewhere outside the repo and lock it down:

   ```sh
   mkdir -p ~/.config/datasette-google-auth
   mv ~/Downloads/<project>-<id>.json ~/.config/datasette-google-auth/live-sa-key.json
   chmod 600 ~/.config/datasette-google-auth/live-sa-key.json
   ```

If your organisation enforces `iam.disableServiceAccountKeyCreation`, step 3
fails: use a project outside that organisation, or ask an admin for an
exception.

The key keeps working until you delete it. Delete it from the **Keys** tab when
you no longer need the live tests (`test_delete_credential` deletes only
Datasette's copy, not the key at Google).

### 4. Create and share the test spreadsheet

1. Create an empty Google Sheet at <https://sheets.new>. Any title and contents
   will do: the tests read the first tab's `A1:C3` whatever is there, and write
   only to their own tab, `datasette-google-auth live`, which they create.
2. Click **Share**, paste the service account's `client_email` (the
   `...@<project>.iam.gserviceaccount.com` address in the key file and on the
   service account's page), choose **Editor**, untick **Notify people**, and
   share.
3. Copy the sheet's URL into `DATASETTE_GOOGLE_AUTH_LIVE_SHEET`.

## When a test fails

- **403 or 404 from Sheets**: the sheet isn't shared with the key's
  `client_email`, or only as Viewer (the write test needs Editor), or the Sheets
  API isn't enabled in the key's project (Google's message says so).
- **`InvalidServiceAccountKey` from `add_service_account`**: Google rejected the
  key (deleted, disabled, or the service account was deleted). Create a new key.
- **A test passes here but the same path fails in the default suite, or the
  reverse**: that's the mock drifting from Google. Fix the mock
  (`tests/mock_google/`) to match what Google did, and note it in the results
  table in `OAUTH_CHECKLIST.md`.
