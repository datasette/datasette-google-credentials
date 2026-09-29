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
