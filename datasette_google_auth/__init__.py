from datasette import hookimpl

from .config import load_config
from .router import router

# Import route modules to trigger registration on the shared router
from .routes import api, pages

_ = (pages, api)


@hookimpl
def register_routes():
    return router.routes()


@hookimpl
def startup(datasette):
    # Validate plugin config first, so a bad config fails startup (with a
    # StartupError naming the bad key) before anything else runs.
    # Internal-DB migrations land here in ticket 03.
    datasette._google_auth_config = load_config(datasette)
