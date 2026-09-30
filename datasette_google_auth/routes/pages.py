"""Page routes (render HTML or redirect) on the shared router.

Pages render ``google_auth_base.html`` with a Vite ``entrypoint`` and a
``page_data`` model from ``page_data.py``. The management page itself
arrives with ticket 14; ``index`` is a placeholder. The OAuth routes are browser
redirects, not API calls, so they live here rather than under ``/api``; the
flow itself is in ``oauth.py``, which turns the errors it expects into error
pages. The ``GoogleAuthError`` catch here is a backstop: none may escape to
Datasette, whose telemetry would record the message on the request span.
"""

from datasette import Forbidden, Response
from pydantic import BaseModel

from ..errors import GoogleAuthError, error_response
from ..oauth import finish_connect, start_connect
from ..page_data import IndexPageData
from ..router import router
from .api import get_status


async def render_page(
    datasette, request, *, title: str, entrypoint: str, page_data: BaseModel
) -> Response:
    """Render a frontend page. ``entrypoint`` is the Vite input's source path
    (``src/pages/<name>/index.ts``, as in ``vite.config.ts``)."""
    return Response.html(
        await datasette.render_template(
            "google_auth_base.html",
            {
                "page_title": title,
                "entrypoint": entrypoint,
                "page_data": page_data.model_dump(),
            },
            request=request,
        )
    )


@router.GET(r"/-/google-auth$")
async def index(datasette, request):
    try:
        status = await get_status(datasette, request)
    except GoogleAuthError as ex:
        return error_response(ex)
    if not (status.can_connect or status.can_add_service_account or status.is_admin):
        raise Forbidden("You don't have permission to manage Google accounts")
    return await render_page(
        datasette,
        request,
        title="Google accounts",
        entrypoint="src/pages/index/index.ts",
        page_data=IndexPageData(status=status),
    )


@router.GET(r"/-/google-auth/connect$")
async def oauth_connect(datasette, request):
    try:
        return await start_connect(datasette, request)
    except GoogleAuthError as ex:
        return error_response(ex)


@router.GET(r"/-/google-auth/oauth/callback$")
async def oauth_callback(datasette, request):
    try:
        return await finish_connect(datasette, request)
    except GoogleAuthError as ex:
        return error_response(ex)
