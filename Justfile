# Ports: Datasette 8021, Vite 5182 (unused by sibling plugins).

# === Frontend ===
# Stubs until ticket 13 adds frontend/ (Svelte 5 + Vite).

frontend *flags:
  @echo "frontend/ does not exist yet (ticket 13)"

frontend-dev *flags:
  @echo "frontend/ does not exist yet (ticket 13)"

# === Type Generation ===
# Stub until ticket 13 adds page_data.py, the typegen script and frontend/.

types:
  @echo "type generation arrives with the frontend (ticket 13)"

# === Formatting ===

format:
  uv run ruff check --fix --quiet
  uv run ruff format

format-check:
  uv run ruff format --check

# === Type Checking + Lint ===

check:
  uv run ty check
  uv run ruff check
  uv run ruff format --check

# === Testing ===

test *flags:
  uv run pytest {{flags}}

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

dev-with-hmr *flags:
  watchexec --stop-signal SIGKILL -e py,html --ignore '*.db' --restart --clear -- \
    just dev -s plugins.datasette-vite.dev_ports.datasette_google_auth 5182 {{flags}}

clean-dev:
  rm -rf .tmp/
