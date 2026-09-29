"""Page routes (render HTML or redirect) on the shared router.

The management page arrives with ticket 14. The OAuth routes are browser
redirects, not API calls, so they live here rather than under ``/api``; the
flow itself is in ``oauth.py``.
"""

from ..oauth import finish_connect, start_connect
from ..router import router


@router.GET(r"/-/google-auth/connect$")
async def oauth_connect(datasette, request):
    return await start_connect(datasette, request)


@router.GET(r"/-/google-auth/oauth/callback$")
async def oauth_callback(datasette, request):
    return await finish_connect(datasette, request)
