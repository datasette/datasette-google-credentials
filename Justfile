# Ports: Datasette 8021, Vite 5187 (unused by sibling plugins; 5182 is
# datasette-sidebar's, 5186 datasette-otel-viewer's).

# === Frontend ===
# Svelte 5 + Vite, built into the package (manifest.json + static/gen/,
# both gitignored). Run `npm install --prefix frontend` once.

frontend *flags:
  npm run build --prefix frontend {{flags}}

frontend-dev *flags:
  npm run dev --prefix frontend -- --port 5187 {{flags}}

frontend-check:
  npm run check --prefix frontend

frontend-format:
  npm run format --prefix frontend

frontend-format-check:
  npm run format:check --prefix frontend

# Documentation screenshots (docs/screenshots/*.png, committed): boots
# throwaway datasettes seeded by the dev-only scripts/shots_seed.py, shoots,
# tears down. Nothing contacts Google. Builds the frontend first so shots
# reflect current code. Pass shot names for a subset, e.g. `just shots index`.
# Needs Chromium once: `npx --prefix frontend playwright install chromium`.
shots *names:
  just frontend
  node frontend/scripts/screenshots.mjs {{names}}

# === Type Generation ===
# Generated types are committed. Every recipe ends by running prettier over
# what it wrote (from inside frontend/, so prettier finds its plugins), so
# `types-check-fresh` and `frontend-format-check` agree (as in datasette-cron).

# Print the JSON API's OpenAPI document (from the router's Pydantic models).
# Importing the router imports the package, which registers every route.
openapi:
  @uv run python -c 'from datasette_google_auth.router import router; import json; print(json.dumps(router.openapi_document_json(), indent=2))'

types-routes:
  just openapi | npx --prefix frontend openapi-typescript > frontend/api.d.ts
  cd frontend && npx prettier --write --log-level warn api.d.ts

types-pagedata:
  uv run scripts/typegen-pagedata.py
  for f in frontend/src/page_data/*_schema.json; do npx --prefix frontend json2ts "$f" > "${f%_schema.json}.types.ts"; done
  cd frontend && npx prettier --write --log-level warn src/page_data/

types:
  just types-routes
  just types-pagedata

types-watch:
  watchexec -e py --clear -- just types

# Regenerate the types and fail if they differ from what's committed
# ("forgot to run `just types`").
types-check-fresh:
  just types
  git diff --exit-code -- frontend/api.d.ts frontend/src/page_data/

# === Formatting ===

format:
  uv run ruff check --fix --quiet
  uv run ruff format
  just frontend-format

format-check:
  uv run ruff format --check
  just frontend-format-check

# === Type Checking + Lint ===

check:
  uv run ty check
  uv run ruff check
  uv run ruff format --check
  just frontend-check

# === Testing ===

# Never collects tests/live/ (pyproject `norecursedirs`) or contacts Google.
test *flags:
  uv run pytest {{flags}}

# Opt-in tests against real Google with a service-account key; Alex runs them,
# never CI. Skips everything, saying why, unless DATASETTE_GOOGLE_AUTH_LIVE_SA_KEY
# (path to a key file) and DATASETTE_GOOGLE_AUTH_LIVE_SHEET are set. Setup and the
# manual OAuth checklist: tests/live/SETUP.md, tests/live/OAUTH_CHECKLIST.md.
test-live *flags:
  uv run pytest tests/live -rs --tb=short {{flags}}

# === Development ===

dev *flags:
  mkdir -p .tmp
  DATASETTE_SECRET=abc123 uv run datasette \
    -s permissions.google-auth-connect true \
    -s permissions.google-auth-add-service-account true \
    -s permissions.google-auth-admin true \
    -s permissions.permissions-debug true \
    --internal .tmp/internal.db \
    -p 8021 \
    --create .tmp/tmp.db \
    --plugins-dir samples \
    {{flags}}

# The viewer installs its own providers at import time, so no
# `opentelemetry-instrument` or OTEL_* env vars here. It stays a `--with ../`
# sibling path until it is on PyPI (same as datasette-cron). Rows land in
# .tmp/otel.db.
# Like `just dev`, plus datasette-otel-viewer: browse spans and metrics at /-/otel.
dev-otel *flags:
  mkdir -p .tmp
  DATASETTE_SECRET=abc123 uv run \
    --no-cache \
    --with ../datasette-otel-viewer \
    datasette \
    -s permissions.google-auth-connect true \
    -s permissions.google-auth-add-service-account true \
    -s permissions.google-auth-admin true \
    -s permissions.permissions-debug true \
    -s permissions.datasette-otel-viewer true \
    -s plugins.datasette-otel-viewer.db_path .tmp/otel.db \
    -s plugins.datasette-otel-viewer.service_name datasette-google-auth \
    --internal .tmp/internal.db \
    -p 8021 \
    --create .tmp/tmp.db \
    --plugins-dir samples \
    {{flags}}

# Regenerate the OpenTelemetry reference in README.md from the registry.
telemetry-doc:
  uv run scripts/telemetry-doc.py

# CI: fail if README's telemetry reference is stale.
telemetry-doc-check:
  uv run scripts/telemetry-doc.py --check

dev-with-hmr *flags:
  watchexec --stop-signal SIGKILL -e py,html --ignore '*.db' --restart --clear -- \
    just dev -s plugins.datasette-vite.dev_ports.datasette_google_auth 5187 {{flags}}

clean-dev:
  rm -rf .tmp/
