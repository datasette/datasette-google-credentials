import time
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from cryptography.fernet import Fernet
from mock_google.oauth import (
    DEFAULT_REDIRECT_URI,
    OAUTH_CLIENT_ID,
    SCOPE_EMAIL,
    SCOPE_OPENID,
    SCOPE_SHEETS,
    GoogleUser,
    s256,
)

from datasette_google_auth import oauth
from datasette_google_auth.crypto import decrypt_credential, encrypt_secret
from datasette_google_auth.errors import (
    CredentialBroken,
    CredentialChanged,
    CredentialNotFound,
)
from datasette_google_auth.internal_db import InternalDB
from datasette_google_auth.oauth import (
    FLOW_COOKIE,
    FLOW_COOKIE_NAMESPACE,
    STATE_NAMESPACE,
    FlowState,
    fetch_oauth_token,
    oauth_cache_key,
    safe_return_to,
    sign_state,
)
from datasette_google_auth.permissions import CONNECT
from datasette_google_auth.token_cache import get_token_cache

ALICE = {"id": "alice"}
BOB = {"id": "bob"}
CAROL = {"id": "carol"}
ALL_SCOPES = [SCOPE_OPENID, SCOPE_EMAIL, SCOPE_SHEETS]
OTHER_USER = GoogleUser("100000000000000000002", "other@example.com")


async def make_datasette(mock_google, **plugin_config):
    datasette = mock_google.datasette(
        plugin_config={"encryption-key": Fernet.generate_key().decode()}
        | plugin_config,
        config={"permissions": {CONNECT: {"id": ["alice", "bob"]}}},
    )
    await datasette.invoke_startup()
    return datasette


def idb(datasette) -> InternalDB:
    return InternalDB(datasette.get_internal_database())


def query(url: str) -> dict[str, str]:
    return {k: v[-1] for k, v in parse_qs(urlsplit(url).query).items()}


def path_and_query(url: str) -> str:
    parts = urlsplit(url)
    return parts.path + ("?" + parts.query if parts.query else "")


async def start(datasette, actor=ALICE, return_to="/data"):
    """GET /connect: returns (authorize URL, flow cookie value)."""
    response = await datasette.client.get(
        "/-/google-auth/connect?" + urlencode({"return_to": return_to}), actor=actor
    )
    assert response.status_code == 302
    return response.headers["location"], response.cookies[FLOW_COOKIE]


async def consent(mock_google, authorize_url):
    """The user approves (or not) at the mock consent screen; returns the
    callback URL Google redirects back to."""
    async with mock_google.client() as google:
        response = await google.get(authorize_url)
    assert response.status_code == 302, response.text
    location = response.headers["location"]
    assert location.startswith(DEFAULT_REDIRECT_URI)
    return location


async def callback(datasette, callback_url, cookie, actor=ALICE):
    cookies = {FLOW_COOKIE: cookie} if cookie is not None else {}
    return await datasette.client.get(
        path_and_query(callback_url), actor=actor, cookies=cookies
    )


async def connect(datasette, mock_google, actor=ALICE, return_to="/data"):
    authorize_url, cookie = await start(datasette, actor, return_to)
    callback_url = await consent(mock_google, authorize_url)
    return await callback(datasette, callback_url, cookie, actor)


def messages(datasette, response):
    raw = response.cookies.get("ds_messages")
    return datasette.unsign(raw, "messages") if raw else []


def cleared_flow_cookie(response) -> bool:
    header = "\n".join(response.headers.get_list("set-cookie"))
    return f"{FLOW_COOKIE}=" in header and "Max-Age=0" in header


# --- Happy path -------------------------------------------------------------


@pytest.mark.asyncio
async def test_connect_redirects_to_google_with_pkce_and_state(mock_google):
    datasette = await make_datasette(mock_google)
    response = await datasette.client.get(
        "/-/google-auth/connect?return_to=/data/t", actor=ALICE
    )
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(
        mock_google.plugin_config()["google_base_urls"]["oauth_authorize"]
    )
    params = query(location)
    assert params["client_id"] == OAUTH_CLIENT_ID
    assert params["redirect_uri"] == DEFAULT_REDIRECT_URI
    assert params["response_type"] == "code"
    assert params["scope"].split() == ALL_SCOPES
    assert params["access_type"] == "offline"
    assert params["prompt"] == "consent"
    assert params["include_granted_scopes"] == "true"
    assert params["code_challenge_method"] == "S256"

    state = datasette.unsign(params["state"], namespace=STATE_NAMESPACE)
    assert state["a"] == "alice"
    assert state["r"] == "/data/t"
    assert abs(state["t"] - time.time()) < 5

    flow = datasette.unsign(
        response.cookies[FLOW_COOKIE], namespace=FLOW_COOKIE_NAMESPACE
    )
    assert flow["n"] == state["n"]
    assert 43 <= len(flow["v"]) <= 128
    assert s256(flow["v"]) == params["code_challenge"]
    assert flow["v"] not in location

    cookie_header = response.headers["set-cookie"]
    assert "HttpOnly" in cookie_header
    assert "SameSite=lax" in cookie_header
    assert "Max-Age=600" in cookie_header
    assert "Path=/-/google-auth/" in cookie_header


@pytest.mark.asyncio
async def test_full_flow_creates_encrypted_credential(mock_google):
    datasette = await make_datasette(mock_google)
    response = await connect(datasette, mock_google)

    assert response.status_code == 302
    assert response.headers["location"] == "/data"
    assert cleared_flow_cookie(response)
    assert messages(datasette, response) == [
        ["Connected Google account user@example.com", datasette.INFO]
    ]

    (row,) = await idb(datasette).list_owned("alice")
    assert row.type == "google_oauth"
    assert row.google_subject == "100000000000000000001"
    assert row.google_email == "user@example.com"
    assert row.label == "user@example.com"
    assert sorted(row.scopes) == sorted(ALL_SCOPES)
    assert row.status == "ok"
    assert row.created_by == "alice"

    # The refresh token is encrypted at rest; the access token isn't stored.
    (exchange,) = [
        r
        for r in mock_google.calls("/token", method="POST")
        if r.form and r.form["grant_type"] == "authorization_code"
    ]
    assert exchange.form["redirect_uri"] == DEFAULT_REDIRECT_URI
    (userinfo,) = mock_google.calls("/v1/userinfo")
    assert userinfo.status == 200
    secret = await decrypt_credential(datasette, row)
    assert set(secret) == {"refresh_token"}
    assert not mock_google.oauth.is_revoked(secret["refresh_token"])
    assert secret["refresh_token"].encode() not in row.secret_encrypted

    # ... it's in the cache instead, so first use doesn't refresh.
    cache = get_token_cache(datasette)

    async def must_not_fetch():
        raise AssertionError("should have been cached")

    token = await cache.get_or_fetch(oauth_cache_key(row), must_not_fetch)
    assert token.scopes == frozenset(ALL_SCOPES)
    assert token.access_token.encode() not in row.secret_encrypted


@pytest.mark.asyncio
async def test_reconnect_same_account_updates_in_place(mock_google):
    datasette = await make_datasette(mock_google)
    await connect(datasette, mock_google)
    (first,) = await idb(datasette).list_owned("alice")
    first_secret = await decrypt_credential(datasette, first)
    await idb(datasette).rename(first.id, "Work account", actor_id="alice")
    await idb(datasette).mark_broken(first.id, "revoked")

    response = await connect(datasette, mock_google)

    assert response.status_code == 302
    (row,) = await idb(datasette).list_owned("alice")
    assert row.id == first.id
    assert row.label == "Work account"
    assert row.status == "ok"
    assert row.status_detail is None
    assert (await decrypt_credential(datasette, row)) != first_secret
    assert row.updated_at is not None
    # The old access token was evicted; only the new one is cached.
    assert len(get_token_cache(datasette)) == 1


@pytest.mark.asyncio
async def test_second_google_account_adds_second_row(mock_google):
    datasette = await make_datasette(mock_google)
    await connect(datasette, mock_google)
    mock_google.oauth.user = OTHER_USER
    await connect(datasette, mock_google)
    rows = await idb(datasette).list_owned("alice")
    assert [(r.google_subject, r.label) for r in rows] == [
        ("100000000000000000001", "user@example.com"),
        (OTHER_USER.sub, OTHER_USER.email),
    ]


@pytest.mark.asyncio
async def test_same_google_account_under_two_users_gives_two_rows(mock_google):
    datasette = await make_datasette(mock_google)
    await connect(datasette, mock_google, actor=ALICE)
    await connect(datasette, mock_google, actor=BOB)
    (alice_row,) = await idb(datasette).list_owned("alice")
    (bob_row,) = await idb(datasette).list_owned("bob")
    assert alice_row.id != bob_row.id
    assert alice_row.google_subject == bob_row.google_subject


@pytest.mark.asyncio
async def test_partial_scope_grant_is_stored(mock_google):
    datasette = await make_datasette(mock_google)
    mock_google.oauth.granted_scopes = {SCOPE_OPENID, SCOPE_EMAIL}
    response = await connect(datasette, mock_google)
    assert response.status_code == 302
    (row,) = await idb(datasette).list_owned("alice")
    assert sorted(row.scopes) == [SCOPE_EMAIL, SCOPE_OPENID]
    (_, warning) = messages(datasette, response)
    assert warning[1] == datasette.WARNING
    assert SCOPE_SHEETS in warning[0]


# --- Callback rejections ----------------------------------------------------


async def assert_rejected(datasette, response, text, status=400):
    assert response.status_code == status
    assert text in response.text
    assert cleared_flow_cookie(response)
    assert await idb(datasette).list_all() == []


@pytest.mark.asyncio
async def test_tampered_state(mock_google):
    datasette = await make_datasette(mock_google)
    authorize_url, cookie = await start(datasette)
    callback_url = await consent(mock_google, authorize_url)
    params = query(callback_url)
    params["state"] = (
        params["state"][:-2]
        + ("A" if params["state"][-2] != "A" else "B")
        + params["state"][-1]
    )
    response = await callback(
        datasette, "/-/google-auth/oauth/callback?" + urlencode(params), cookie
    )
    await assert_rejected(datasette, response, "invalid")
    assert not mock_google.calls("/token")


@pytest.mark.asyncio
async def test_state_signed_for_different_return_to_rejected(mock_google):
    # A state re-signed by an attacker would need DATASETTE_SECRET; a state
    # from another namespace (e.g. a flash message) must not be accepted.
    datasette = await make_datasette(mock_google)
    authorize_url, cookie = await start(datasette)
    params = query(await consent(mock_google, authorize_url))
    params["state"] = datasette.sign({"a": "alice", "r": "/", "n": "x", "t": 0})
    response = await callback(
        datasette, "/-/google-auth/oauth/callback?" + urlencode(params), cookie
    )
    await assert_rejected(datasette, response, "invalid")


@pytest.mark.asyncio
async def test_expired_state(mock_google):
    datasette = await make_datasette(mock_google)
    authorize_url, cookie = await start(datasette)
    params = query(await consent(mock_google, authorize_url))
    old = datasette.unsign(params["state"], namespace=STATE_NAMESPACE)
    params["state"] = sign_state(
        datasette, FlowState("alice", "/data", old["n"], int(time.time()) - 601)
    )
    response = await callback(
        datasette, "/-/google-auth/oauth/callback?" + urlencode(params), cookie
    )
    await assert_rejected(datasette, response, "expired")
    assert not mock_google.calls("/token")


@pytest.mark.asyncio
async def test_nonce_mismatch(mock_google):
    datasette = await make_datasette(mock_google)
    authorize_url, _ = await start(datasette)
    callback_url = await consent(mock_google, authorize_url)
    # A second connect (another tab, or an attacker's own flow) replaced the
    # cookie: the first callback no longer matches.
    _, other_cookie = await start(datasette)
    response = await callback(datasette, callback_url, other_cookie)
    await assert_rejected(datasette, response, "match this browser session")
    assert not mock_google.calls("/token")


@pytest.mark.asyncio
async def test_missing_flow_cookie(mock_google):
    datasette = await make_datasette(mock_google)
    authorize_url, _ = await start(datasette)
    callback_url = await consent(mock_google, authorize_url)
    response = await callback(datasette, callback_url, None)
    await assert_rejected(datasette, response, "match this browser session")


@pytest.mark.asyncio
async def test_different_actor_at_callback(mock_google):
    datasette = await make_datasette(mock_google)
    authorize_url, cookie = await start(datasette, actor=ALICE)
    callback_url = await consent(mock_google, authorize_url)
    response = await callback(datasette, callback_url, cookie, actor=BOB)
    await assert_rejected(datasette, response, "different user")
    assert not mock_google.calls("/token")


@pytest.mark.asyncio
async def test_bad_pkce_verifier_rejected_by_google(mock_google):
    datasette = await make_datasette(mock_google)
    authorize_url, cookie = await start(datasette)
    callback_url = await consent(mock_google, authorize_url)
    flow = datasette.unsign(cookie, namespace=FLOW_COOKIE_NAMESPACE)
    forged = datasette.sign(
        {"v": "x" * 64, "n": flow["n"]}, namespace=FLOW_COOKIE_NAMESPACE
    )
    response = await callback(datasette, callback_url, forged)
    await assert_rejected(datasette, response, "Google rejected the connection")
    (exchange,) = mock_google.calls("/token", method="POST")
    assert exchange.status == 400
    assert "x" * 64 not in response.text


@pytest.mark.asyncio
async def test_access_denied_flashes_and_returns(mock_google):
    datasette = await make_datasette(mock_google)
    mock_google.oauth.deny = True
    response = await connect(datasette, mock_google, return_to="/data/t")
    assert response.status_code == 302
    assert response.headers["location"] == "/data/t"
    assert messages(datasette, response) == [
        ["Google connection cancelled", datasette.WARNING]
    ]
    assert cleared_flow_cookie(response)
    assert await idb(datasette).list_all() == []
    assert not mock_google.calls("/token")


@pytest.mark.asyncio
async def test_error_with_bad_state_is_not_redirected(mock_google):
    datasette = await make_datasette(mock_google)
    response = await datasette.client.get(
        "/-/google-auth/oauth/callback?error=access_denied&state=nope", actor=ALICE
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_missing_refresh_token(mock_google, monkeypatch):
    datasette = await make_datasette(mock_google)
    real_exchange = mock_google.oauth.exchange_code

    def exchange_without_refresh_token(form):
        reply = real_exchange(form)
        reply.pop("refresh_token")
        return reply

    monkeypatch.setattr(
        mock_google.oauth, "exchange_code", exchange_without_refresh_token
    )
    response = await connect(datasette, mock_google)
    await assert_rejected(
        datasette, response, "https://myaccount.google.com/linkedapps"
    )


@pytest.mark.asyncio
async def test_token_endpoint_failure_is_502(mock_google):
    datasette = await make_datasette(mock_google)
    authorize_url, cookie = await start(datasette)
    callback_url = await consent(mock_google, authorize_url)
    mock_google.faults.fail("/token", 500)
    response = await callback(datasette, callback_url, cookie)
    await assert_rejected(datasette, response, "HTTP 500", status=502)


@pytest.mark.asyncio
async def test_callback_never_echoes_secrets(mock_google):
    datasette = await make_datasette(mock_google)
    authorize_url, cookie = await start(datasette)
    callback_url = await consent(mock_google, authorize_url)
    code = query(callback_url)["code"]
    response = await callback(datasette, callback_url, cookie)
    (row,) = await idb(datasette).list_owned("alice")
    refresh_token = (await decrypt_credential(datasette, row))["refresh_token"]
    everything = response.text + str(response.headers)
    for secret in (code, refresh_token):
        assert secret not in everything


# --- Access, config ---------------------------------------------------------


@pytest.mark.parametrize(
    "path", ["/-/google-auth/connect", "/-/google-auth/oauth/callback"]
)
@pytest.mark.asyncio
async def test_oauth_not_configured_is_404(mock_google, path):
    datasette = await make_datasette(mock_google, client_id=None, client_secret=None)
    response = await datasette.client.get(path, actor=ALICE)
    assert response.status_code == 404


@pytest.mark.parametrize("actor", [None, CAROL])
@pytest.mark.parametrize(
    "path", ["/-/google-auth/connect", "/-/google-auth/oauth/callback"]
)
@pytest.mark.asyncio
async def test_needs_connect_permission(mock_google, actor, path):
    datasette = await make_datasette(mock_google)
    response = await datasette.client.get(path, actor=actor)
    assert response.status_code == 403
    assert FLOW_COOKIE not in response.cookies


@pytest.mark.asyncio
async def test_connect_without_encryption_key(mock_google):
    datasette = mock_google.datasette(
        config={"permissions": {CONNECT: {"id": "alice"}}}
    )
    await datasette.invoke_startup()
    response = await datasette.client.get("/-/google-auth/connect", actor=ALICE)
    assert response.status_code == 503
    assert "encryption-key" in response.text


@pytest.mark.asyncio
async def test_redirect_uri_override(mock_google):
    override = "https://datasette.example/-/google-auth/oauth/callback"
    datasette = await make_datasette(mock_google, redirect_uri=override)
    authorize_url, _ = await start(datasette)
    assert query(authorize_url)["redirect_uri"] == override


# --- return_to --------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "//evil.com",
        "https://evil.com",
        "/\\evil.com",
        "/%0d%0aSet-Cookie:x=y",
        "/\r\nSet-Cookie:x=y",
        "%2F%2Fevil.com",
        "/%5Cevil.com",
        "/\t/evil.com",
        "javascript:alert(1)",
        "evil.com",
        "",
        None,
    ],
)
def test_safe_return_to_rejects(value):
    assert safe_return_to(value) == "/-/google-auth"


@pytest.mark.parametrize("value", ["/", "/data", "/data/t?_sort=id&x=1#frag"])
def test_safe_return_to_accepts(value):
    assert safe_return_to(value) == value


@pytest.mark.parametrize(
    "return_to", ["//evil.com", "https://evil.com", "/\\evil.com", "/%0d%0a"]
)
@pytest.mark.asyncio
async def test_open_redirect_falls_back(mock_google, return_to):
    datasette = await make_datasette(mock_google)
    authorize_url, _ = await start(datasette, return_to=return_to)
    state = datasette.unsign(query(authorize_url)["state"], namespace=STATE_NAMESPACE)
    assert state["r"] == "/-/google-auth"
    mock_google.oauth.deny = True
    response = await connect(datasette, mock_google, return_to=return_to)
    assert response.headers["location"] == "/-/google-auth"


# --- Refresh ----------------------------------------------------------------


async def connected_row(datasette, mock_google):
    await connect(datasette, mock_google)
    (row,) = await idb(datasette).list_owned("alice")
    return row


@pytest.mark.asyncio
async def test_refresh_returns_token_with_granted_scopes(mock_google):
    datasette = await make_datasette(mock_google)
    row = await connected_row(datasette, mock_google)
    token = await fetch_oauth_token(datasette, row, actor_id="alice")
    assert token.scopes == frozenset(ALL_SCOPES)
    assert token.expires_at > time.time() + 3000
    (refresh,) = [
        r
        for r in mock_google.calls("/token", method="POST")
        if r.form and r.form["grant_type"] == "refresh_token"
    ]
    assert refresh.form["client_id"] == OAUTH_CLIENT_ID
    assert "client_secret" in refresh.form
    # No rotation: the row (and its cache key) is untouched.
    assert await idb(datasette).get(row.id) == row


@pytest.mark.asyncio
async def test_refresh_invalid_grant_marks_broken(mock_google):
    datasette = await make_datasette(mock_google)
    row = await connected_row(datasette, mock_google)
    refresh_token = (await decrypt_credential(datasette, row))["refresh_token"]
    async with mock_google.client() as google:
        await google.post("/revoke", data={"token": refresh_token})

    with pytest.raises(CredentialBroken) as excinfo:
        await fetch_oauth_token(datasette, row, actor_id="alice")

    assert excinfo.value.credential_id == row.id
    assert excinfo.value.detail == "Google access was revoked or expired — reconnect"
    assert excinfo.value.reconnect_url == "/-/google-auth/connect"
    assert refresh_token not in str(excinfo.value)
    broken = await idb(datasette).get(row.id)
    assert broken is not None
    assert broken.status == "broken"
    assert broken.status_detail == "Google access was revoked or expired — reconnect"
    assert len(get_token_cache(datasette)) == 0

    # Reconnecting fixes it.
    await connect(datasette, mock_google)
    fixed = await idb(datasette).get(row.id)
    assert fixed is not None and fixed.status == "ok"


@pytest.mark.asyncio
async def test_rotated_refresh_token_is_stored(mock_google):
    datasette = await make_datasette(mock_google)
    row = await connected_row(datasette, mock_google)
    old = (await decrypt_credential(datasette, row))["refresh_token"]
    mock_google.oauth.rotate_refresh_tokens = True

    token = await fetch_oauth_token(datasette, row, actor_id="alice")

    updated = await idb(datasette).get(row.id)
    assert updated is not None
    new = (await decrypt_credential(datasette, updated))["refresh_token"]
    assert new != old
    assert mock_google.oauth.is_revoked(old)
    assert not mock_google.oauth.is_revoked(new)
    assert updated.updated_at != row.updated_at
    assert updated.status == "ok"

    # The new token is cached under the new secret version, so the next
    # lookup doesn't refresh (and rotate) again.
    async def must_not_fetch():
        raise AssertionError("should have been cached")

    cached = await get_token_cache(datasette).get_or_fetch(
        oauth_cache_key(updated), must_not_fetch
    )
    assert cached == token

    # And the stored token works.
    mock_google.oauth.rotate_refresh_tokens = False
    await fetch_oauth_token(datasette, updated, actor_id="alice")


# --- Races: the row changes between the read and the write ------------------


def patch_refresh(monkeypatch, before=None, after=None):
    """Wrap oauth.refresh_access_token: ``before()`` runs before the real
    call, ``after(granted)`` after it, each on the first call only. Returns
    the list of calls made."""
    real = oauth.refresh_access_token
    calls = []

    async def wrapped(*args, **kwargs):
        calls.append(args[2])
        first = len(calls) == 1
        if first and before is not None:
            await before()
        granted = await real(*args, **kwargs)
        if first and after is not None:
            await after(granted)
        return granted

    monkeypatch.setattr(oauth, "refresh_access_token", wrapped)
    return calls


def refresh_posts(mock_google):
    return [
        r
        for r in mock_google.calls("/token", method="POST")
        if r.form and r.form["grant_type"] == "refresh_token"
    ]


@pytest.mark.asyncio
async def test_update_secret_and_mark_broken_compare_and_swap(mock_google):
    datasette = await make_datasette(mock_google)
    row = await connected_row(datasette, mock_google)
    db = idb(datasette)
    assert not await db.mark_broken(row.id, "x", expected_secret=b"other")
    assert not await db.update_secret(
        row.id, b"new", actor_id="alice", expected_secret=b"other"
    )
    assert await db.get(row.id) == row
    assert await db.mark_broken(row.id, "x", expected_secret=row.secret_encrypted)
    broken = await db.get(row.id)
    assert broken is not None and broken.status == "broken"


@pytest.mark.asyncio
async def test_reconnect_during_refresh_is_not_marked_broken(mock_google, monkeypatch):
    datasette = await make_datasette(mock_google)
    row = await connected_row(datasette, mock_google)
    old = (await decrypt_credential(datasette, row))["refresh_token"]
    async with mock_google.client() as google:
        await google.post("/revoke", data={"token": old})

    async def reconnect():
        response = await connect(datasette, mock_google)
        assert response.status_code == 302

    calls = patch_refresh(monkeypatch, before=reconnect)
    token = await fetch_oauth_token(datasette, row, actor_id="alice")

    # Google rejected the old secret, but the row now holds the reconnect's.
    current = await idb(datasette).get(row.id)
    assert current is not None
    assert current.status == "ok"
    assert current.status_detail is None
    new = (await decrypt_credential(datasette, current))["refresh_token"]
    assert new != old and not mock_google.oauth.is_revoked(new)
    # The retry used the token the reconnect cached: no second refresh.
    assert calls == [old]
    assert len(refresh_posts(mock_google)) == 1
    assert token.scopes == frozenset(ALL_SCOPES)
    cached = await get_token_cache(datasette).get_or_fetch(
        oauth_cache_key(current), fail_fetch
    )
    assert cached == token


async def fail_fetch():
    raise AssertionError("should have been cached")


@pytest.mark.asyncio
async def test_reconnect_during_rotation_keeps_reconnected_secret(
    mock_google, monkeypatch
):
    datasette = await make_datasette(mock_google)
    row = await connected_row(datasette, mock_google)
    old = (await decrypt_credential(datasette, row))["refresh_token"]
    mock_google.oauth.rotate_refresh_tokens = True
    rotated = []

    async def reconnect_after(granted):
        rotated.append(granted.refresh_token)
        response = await connect(datasette, mock_google)
        assert response.status_code == 302

    calls = patch_refresh(monkeypatch, after=reconnect_after)
    token = await fetch_oauth_token(datasette, row, actor_id="alice")

    current = await idb(datasette).get(row.id)
    assert current is not None
    stored = (await decrypt_credential(datasette, current))["refresh_token"]
    # The rotated token (from the superseded grant) didn't overwrite the
    # reconnect's refresh token.
    assert rotated and rotated[0] not in (None, stored)
    assert stored != old
    assert not mock_google.oauth.is_revoked(stored)
    assert current.status == "ok"
    assert calls == [old]
    cached = await get_token_cache(datasette).get_or_fetch(
        oauth_cache_key(current), fail_fetch
    )
    assert cached == token


@pytest.mark.asyncio
async def test_row_changing_on_retry_too_raises_credential_changed(
    mock_google, monkeypatch
):
    datasette = await make_datasette(mock_google)
    row = await connected_row(datasette, mock_google)
    counter = iter(range(100))

    async def reconnect_then_reject(*args, **kwargs):
        # Every refresh races a reconnect (and a cache eviction), then Google
        # rejects the old secret.
        await idb(datasette).upsert_oauth(
            "alice",
            row.google_subject or "",
            google_email=row.google_email,
            label=row.label,
            scopes=row.scopes,
            secret_encrypted=encrypt_secret(
                datasette, {"refresh_token": f"1//new-{next(counter)}"}
            ),
            actor_id="alice",
        )
        get_token_cache(datasette).evict(row.id)
        raise CredentialBroken("Token has been expired or revoked.")

    monkeypatch.setattr(oauth, "refresh_access_token", reconnect_then_reject)
    with pytest.raises(CredentialChanged) as excinfo:
        await fetch_oauth_token(datasette, row, actor_id="alice")
    assert excinfo.value.credential_id == row.id
    assert excinfo.value.code == "credential_changed"
    current = await idb(datasette).get(row.id)
    assert current is not None and current.status == "ok"


@pytest.mark.asyncio
async def test_row_deleted_during_refresh_raises_not_found(mock_google, monkeypatch):
    datasette = await make_datasette(mock_google)
    row = await connected_row(datasette, mock_google)

    async def delete_then_reject(*args, **kwargs):
        await idb(datasette).delete(row.id)
        raise CredentialBroken("Token has been expired or revoked.")

    monkeypatch.setattr(oauth, "refresh_access_token", delete_then_reject)
    with pytest.raises(CredentialNotFound):
        await fetch_oauth_token(datasette, row, actor_id="alice")
    assert await idb(datasette).list_all() == []
