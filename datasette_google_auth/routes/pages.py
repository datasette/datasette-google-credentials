"""Page routes (render HTML or redirect) on the shared router.

The management page arrives with ticket 14. The OAuth routes are browser
redirects, not API calls, so they live here rather than under ``/api``; the
flow itself is in ``oauth.py``, which turns the errors it expects into error
pages. The ``GoogleAuthError`` catch here is a backstop: none may escape to
Datasette, whose telemetry would record the message on the request span.
"""

from ..errors import GoogleAuthError, error_response
from ..oauth import finish_connect, start_connect
from ..router import router


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
