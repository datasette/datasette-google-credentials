"""Page routes (render HTML or redirect) on the shared router.

Pages render ``google_auth_base.html`` with a Vite ``entrypoint`` and a
``page_data`` model from ``page_data.py``. ``index`` is the management page
(ticket 14); its Svelte app is ``frontend/src/pages/index/``. The OAuth routes are browser
redirects, not API calls, so they live here rather than under ``/api``; the
flow itself is in ``oauth.py``, which turns the errors it expects into error
pages. The ``GoogleAuthError`` catch here is a backstop: none may escape to
Datasette, whose telemetry would record the message on the request span.
"""

from datasette import Forbidden, Response
from pydantic import BaseModel

from ..errors import GoogleAuthError, error_response
from ..oauth import DEFAULT_RETURN_TO, connect_url, finish_connect, start_connect
from ..page_data import IndexPageData, ShareDialog
from ..router import router
from ..service import list_with_access
from ..sharing import share_assets, share_features
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
    """The management page. Anonymous actors get 403 (no login-URL API to
    redirect to, as D24). Any signed-in actor gets the page, even without a
    google-auth action: they may have service accounts shared with them."""
    actor = request.actor
    if not actor or actor.get("id") is None:
        raise Forbidden("Sign in to manage your Google accounts")
    try:
        status = await get_status(datasette, request)
        credentials = await list_with_access(datasette, actor)
    except GoogleAuthError as ex:
        return error_response(ex)
    return await render_page(
        datasette,
        request,
        title="Google accounts",
        entrypoint="src/pages/index/index.ts",
        page_data=IndexPageData(
            status=status,
            credentials=credentials,
            actor_id=str(actor["id"]),
            connect_url=connect_url(
                datasette, return_to=datasette.urls.path(DEFAULT_RETURN_TO)
            ),
            share=ShareDialog(features=share_features())
            if share_assets(datasette) is not None
            else None,
        ),
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
