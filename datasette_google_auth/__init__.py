from datasette import hookimpl
from sqlite_utils import Database as SqliteUtilsDatabase

from .config import load_config
from .internal_migrations import internal_migrations
from .router import router

# Import route modules to trigger registration on the shared router
from .routes import api, pages

_ = (pages, api)


@hookimpl
def register_routes():
    return router.routes()


@hookimpl
def startup(datasette):
    async def inner():
        # Validate plugin config first, so a bad config fails startup (with a
        # StartupError naming the bad key) before anything touches the
        # internal database.
        datasette._google_auth_config = load_config(datasette)

        def apply_google_auth_migrations(connection):
            internal_migrations.apply(SqliteUtilsDatabase(connection))

        await datasette.get_internal_database().execute_write_fn(
            apply_google_auth_migrations
        )

    return inner
