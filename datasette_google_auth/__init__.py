from datasette import hookimpl

from .router import router

# Import route modules to trigger registration on the shared router
from .routes import api, pages

_ = (pages, api)


@hookimpl
def register_routes():
    return router.routes()


@hookimpl
def startup(datasette):
    # Placeholder: config validation and internal-DB migrations land here
    # (tickets 02 and 03).
    pass
