"""``datasette google-auth ...`` commands, registered by ``register_commands``.

- ``generate-key`` prints a new Fernet key for ``encryption-key``.
- ``rotate-keys`` re-encrypts every stored credential with the first
  configured key. It rebuilds Datasette from the same ``--internal``,
  ``-c/--config`` and ``-s/--setting`` options ``datasette serve`` takes (the
  pattern datasette-accounts' CLI uses), so ``$env`` / ``$file`` references
  resolve exactly as they do for the server.
"""

from __future__ import annotations

import asyncio

import click
from cryptography.fernet import Fernet


@click.group(name="google-auth")
def google_auth():
    "Commands for datasette-google-auth"


@google_auth.command(name="generate-key")
def generate_key():
    """Print a new encryption key for the encryption-key setting.

    Keep it secret: anyone with it and a copy of the internal database can
    read every stored Google credential.
    """
    click.echo(Fernet.generate_key().decode())


@google_auth.command(name="rotate-keys")
@click.option(
    "--internal",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    envvar="DATASETTE_INTERNAL",
    help="Path to the persistent Datasette internal database",
)
@click.option(
    "-c",
    "--config",
    type=click.File(mode="r"),
    help="Path to the JSON/YAML Datasette configuration file",
)
@click.option(
    "-s",
    "--setting",
    "settings",
    type=(str, str),
    multiple=True,
    help="nested.key, value setting to use in Datasette configuration",
)
def rotate_keys(internal, config, settings):
    """Re-encrypt every stored credential with the first encryption-key.

    To rotate: put a new key first in the encryption-key list, keeping the
    old one after it, run this with the same configuration, then drop the old
    key.
    """
    result = asyncio.run(_rotate_keys(internal, config, settings))
    click.echo(
        f"Re-encrypted {len(result.rotated)} credential(s) with the primary key;"
        f" {len(result.current)} already current."
    )
    if result.undecryptable:
        raise click.ClickException(
            f"{len(result.undecryptable)} credential(s) could not be decrypted"
            " with any configured key and were left unchanged: "
            + ", ".join(result.undecryptable)
        )


async def _rotate_keys(internal, config, settings):
    # Imported lazily: this module loads while Datasette's own CLI imports.
    from datasette.app import Datasette
    from datasette.utils import (
        StartupError,
        deep_dict_update,
        pairs_to_nested_config,
        parse_metadata,
    )

    from .crypto import rotate_all_credentials
    from .errors import EncryptionNotConfigured

    # Same merge as `datasette serve`: -s settings layered over -c config.
    config_data = (parse_metadata(config.read()) if config else None) or {}
    if settings:
        deep_dict_update(config_data, pairs_to_nested_config(list(settings)))
    datasette = Datasette(internal=internal, config=config_data)
    try:
        await datasette.invoke_startup()
        return await rotate_all_credentials(datasette)
    except (StartupError, EncryptionNotConfigured) as error:
        raise click.ClickException(str(error)) from None
    finally:
        datasette.close()
