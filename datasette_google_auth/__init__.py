"""datasette-google-auth: Google credentials and a token broker for Datasette.

This module holds the plugin hooks and re-exports the consumer API (D11);
the implementation lives in ``broker.py`` and ``errors.py``.
"""

from datasette import hookimpl
from datasette.utils import StartupError
from sqlite_utils import Database as SqliteUtilsDatabase

from .broker import Credential, get_credential, list_credentials
from .config import PLUGIN_NAME, load_config
from .crypto import InvalidEncryptionKey, build_box
from .errors import (
    CredentialBroken,
    CredentialChanged,
    CredentialForbidden,
    CredentialNotFound,
    CredentialUndecryptable,
    EncryptionNotConfigured,
    GoogleAuthError,
    GoogleTokenError,
    InvalidServiceAccountKey,
    MissingScopes,
    error_response,
)
from .internal_migrations import internal_migrations
from .models import CredentialInfo
from .oauth import connect_url
from .permissions import acl_roles, actions
from .router import router

# Import route modules to trigger registration on the shared router
from .routes import api, pages
from .token_cache import TokenCache

_ = (pages, api)

__all__ = [
    "Credential",
    "CredentialBroken",
    "CredentialChanged",
    "CredentialForbidden",
    "CredentialInfo",
    "CredentialNotFound",
    "CredentialUndecryptable",
    "EncryptionNotConfigured",
    "GoogleAuthError",
    "GoogleTokenError",
    "InvalidServiceAccountKey",
    "MissingScopes",
    "connect_url",
    "error_response",
    "get_credential",
    "list_credentials",
]


@hookimpl
def register_routes():
    return router.routes()


@hookimpl
def register_actions(datasette):
    return actions()


@hookimpl
def datasette_acl_roles(datasette):
    return acl_roles()


@hookimpl
def register_commands(cli):
    from .cli import google_auth

    cli.add_command(google_auth)


@hookimpl
def startup(datasette):
    async def inner():
        # Validate plugin config first, so a bad config fails startup (with a
        # StartupError naming the bad key) before anything touches the
        # internal database.
        config = load_config(datasette)
        try:
            build_box(config.encryption_keys)
        except InvalidEncryptionKey as error:
            raise StartupError(
                f"Invalid {PLUGIN_NAME} plugin configuration:\n"
                f"  encryption-key: {error}"
            ) from None
        datasette._google_auth_config = config
        # Access tokens live only in memory, per process (D7).
        datasette._google_auth_tokens = TokenCache()

        def apply_google_auth_migrations(connection):
            internal_migrations.apply(SqliteUtilsDatabase(connection))

        await datasette.get_internal_database().execute_write_fn(
            apply_google_auth_migrations
        )

    return inner
