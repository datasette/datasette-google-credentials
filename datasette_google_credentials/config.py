"""The plugin's own configuration: the ``plugins: datasette-google-credentials:`` block.

Validated once at startup. A typo'd key or a bad value fails startup with a
``StartupError`` naming the field, rather than being silently ignored.

Secret-bearing keys (``encryption-key``, ``client_secret``) are named so that
Datasette's ``/-/config`` redaction (key names containing ``key``/``secret``)
hides them, and are left out of ``repr(config)``. Validation errors never
echo input values.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from datasette.utils import StartupError
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

if TYPE_CHECKING:
    from datasette.app import Datasette

PLUGIN_NAME = "datasette-google-credentials"

# Always requested: `openid` gives the stable `sub`, `email` labels the
# credential with its Google account (D4, D9).
REQUIRED_SCOPES = ("openid", "email")

logger = logging.getLogger(__name__)


class GoogleBaseUrls(BaseModel):
    """Google endpoints. Override only to point tests at a mock server."""

    model_config = ConfigDict(
        extra="forbid", hide_input_in_errors=True, use_attribute_docstrings=True
    )

    oauth_authorize: str = "https://accounts.google.com/o/oauth2/v2/auth"
    oauth_token: str = "https://oauth2.googleapis.com/token"
    oauth_revoke: str = "https://oauth2.googleapis.com/revoke"
    userinfo: str = "https://openidconnect.googleapis.com/v1/userinfo"


class Config(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        hide_input_in_errors=True,
        title="datasette-google-credentials plugin config",
        use_attribute_docstrings=True,
    )

    encryption_key: str | list[str] | None = Field(
        None, alias="encryption-key", repr=False
    )
    """Fernet key used to encrypt stored secrets, usually
    ``{"$env": "DATASETTE_GOOGLE_CREDENTIALS_KEY"}``. A list enables rotation: the
    first key encrypts, all keys decrypt. Unset means credentials cannot be
    created."""

    client_id: str | None = None
    """OAuth client ID. With ``client_secret``, enables "Connect Google"."""

    client_secret: str | None = Field(None, repr=False)
    """OAuth client secret, usually via ``$env``."""

    scopes: list[str] = Field(
        default_factory=lambda: [
            "openid",
            "email",
            "https://www.googleapis.com/auth/spreadsheets",
        ]
    )
    """OAuth scopes requested on connect. ``openid`` and ``email`` are always
    added if missing."""

    redirect_uri: str | None = None
    """Override the OAuth redirect URI (for proxies). Defaults to the absolute
    URL of ``/-/google-credentials/oauth/callback``."""

    google_base_urls: GoogleBaseUrls = Field(default_factory=GoogleBaseUrls)
    """Test-only overrides for Google endpoints."""

    @field_validator("scopes")
    @classmethod
    def _ensure_required_scopes(cls, value: list[str]) -> list[str]:
        missing = [scope for scope in REQUIRED_SCOPES if scope not in value]
        if missing:
            logger.info(
                "%s: adding required OAuth scopes %s to configured scopes",
                PLUGIN_NAME,
                ", ".join(missing),
            )
        return missing + value

    @property
    def encryption_keys(self) -> list[str]:
        """Configured encryption keys, newest first; empty if unset."""
        if self.encryption_key is None:
            return []
        if isinstance(self.encryption_key, str):
            return [self.encryption_key] if self.encryption_key else []
        return [key for key in self.encryption_key if key]


def oauth_configured(config: Config) -> bool:
    return bool(config.client_id) and bool(config.client_secret)


def encryption_configured(config: Config) -> bool:
    return bool(config.encryption_keys)


def _format_error(error: ValidationError) -> str:
    # Only field paths and messages: never the input values, which may be
    # key material or a client secret.
    lines = [f"Invalid {PLUGIN_NAME} plugin configuration:"]
    for detail in error.errors(include_input=False, include_url=False):
        loc = ".".join(str(part) for part in detail["loc"]) or "(root)"
        lines.append(f"  {loc}: {detail['msg']}")
    return "\n".join(lines)


def load_config(datasette: Datasette) -> Config:
    """Validate the plugin config (``$env``/``$file`` already resolved).

    Raises ``StartupError`` with a message naming each bad key.
    """
    raw = datasette.plugin_config(PLUGIN_NAME) or {}
    try:
        return Config.model_validate(raw)
    except ValidationError as error:
        raise StartupError(_format_error(error)) from None


def get_config(datasette: Datasette) -> Config:
    """The config validated at startup (validates now if startup hasn't run)."""
    config = getattr(datasette, "_google_credentials_config", None)
    if config is None:
        config = load_config(datasette)
        setattr(datasette, "_google_credentials_config", config)  # noqa: B010
    return config
