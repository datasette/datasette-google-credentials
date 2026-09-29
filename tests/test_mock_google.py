"""Sanity checks for the in-process mock Google server (tests/mock_google)."""

import socket
import time
from urllib.parse import parse_qs, urlsplit

import httpx2
import jwt
import pytest
from fixtures_google import GOOGLE_BASE_URLS, SHEETS_BASE, NetworkBlocked
from mock_google.keys import ID_TOKEN_KID, SA_TEST, id_token_key
from mock_google.oauth import (
    DEFAULT_REDIRECT_URI,
    OAUTH_CLIENT_ID,
    OAUTH_CLIENT_SECRET,
    SCOPE_SHEETS,
    SCOPE_SHEETS_RO,
    GoogleUser,
    s256,
)

from datasette_google_auth import http
from datasette_google_auth.config import get_config

VERIFIER = "v" * 43 + "-._~0123456789"
SCOPES = f"openid email {SCOPE_SHEETS}"


def authorize_params(**overrides):
    params = {
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": DEFAULT_REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPES,
        "state": "state-123",
        "code_challenge": s256(VERIFIER),
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
    }
    params.update(overrides)
    return {k: v for k, v in params.items() if v is not None}


async def authorize(client, **overrides):
    response = await client.get(
        "/o/oauth2/v2/auth", params=authorize_params(**overrides)
    )
    assert response.status_code == 302, response.text
    location = response.headers["location"]
    assert location.startswith(DEFAULT_REDIRECT_URI + "?")
    return {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}


async def exchange(client, code, verifier=VERIFIER, **overrides):
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
        "redirect_uri": DEFAULT_REDIRECT_URI,
    }
    form.update(overrides)
    return await client.post("/token", data={k: v for k, v in form.items() if v})


async def connect(client, **authorize_overrides):
    """Run consent + code exchange; return the token response JSON."""
    reply = await authorize(client, **authorize_overrides)
    response = await exchange(client, reply["code"])
    assert response.status_code == 200, response.text
    return response.json()


async def refresh(client, refresh_token, **overrides):
    form = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
    }
    form.update(overrides)
    return await client.post("/token", data=form)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def sa_assertion(key, scope=SCOPE_SHEETS, **claims):
    now = int(time.time())
    payload = {
        "iss": key.client_email,
        "scope": scope,
        "aud": GOOGLE_BASE_URLS["oauth_token"],
        "iat": now,
        "exp": now + 3600,
    }
    payload.update(claims)
    return jwt.encode(
        payload, key.private_key, algorithm="RS256", headers={"kid": key.private_key_id}
    )


async def sa_token(client, key, **claims):
    return await client.post(
        "/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": sa_assertion(key, **claims),
        },
    )


# --- isolation --------------------------------------------------------------


def test_sockets_are_blocked():
    with pytest.raises(NetworkBlocked):
        socket.create_connection(("127.0.0.1", 9), timeout=1)
    with pytest.raises(NetworkBlocked):
        socket.getaddrinfo("oauth2.googleapis.com", 443)


@pytest.mark.asyncio
async def test_real_google_is_unreachable():
    async with httpx2.AsyncClient() as client:
        with pytest.raises((NetworkBlocked, httpx2.ConnectError)):
            await client.post("https://oauth2.googleapis.com/token")


@pytest.mark.asyncio
async def test_datasette_is_wired_to_mock(mock_google):
    datasette = mock_google.datasette()
    await datasette.invoke_startup()
    urls = get_config(datasette).google_base_urls
    assert urls.oauth_token == "http://mock-google/token"
    async with http.client(datasette) as client:
        response = await client.post(urls.oauth_token, data={"grant_type": "nope"})
    assert response.json()["error"] == "unsupported_grant_type"
    [call] = mock_google.calls("/token")
    assert (call.host, call.form) == ("mock-google", {"grant_type": "nope"})


@pytest.mark.asyncio
async def test_unexpected_host_is_refused_and_logged(mock_google):
    async with mock_google.client() as client:
        response = await client.post("https://oauth2.googleapis.com/token")
    assert response.status_code == 421
    assert [c.url for c in mock_google.requests] == ["oauth2.googleapis.com/token"]


# --- authorization code + PKCE -------------------------------------------------


@pytest.mark.asyncio
async def test_auth_code_pkce_happy_path(mock_google):
    async with mock_google.client() as client:
        reply = await authorize(client)
        assert reply["state"] == "state-123"
        assert set(reply["scope"].split()) == set(SCOPES.split())
        response = await exchange(client, reply["code"])
        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == {
            "access_token",
            "refresh_token",
            "expires_in",
            "scope",
            "token_type",
            "id_token",
        }
        assert set(body["scope"].split()) == set(SCOPES.split())
        claims = jwt.decode(
            body["id_token"],
            id_token_key().public_key(),
            algorithms=["RS256"],
            audience=OAUTH_CLIENT_ID,
            issuer="https://accounts.google.com",
        )
        assert jwt.get_unverified_header(body["id_token"])["kid"] == ID_TOKEN_KID
        assert (claims["sub"], claims["email"]) == (
            "100000000000000000001",
            "user@example.com",
        )

        info = await client.get("/v1/userinfo", headers=bearer(body["access_token"]))
        assert info.json() == {
            "sub": "100000000000000000001",
            "email": "user@example.com",
            "email_verified": True,
        }

        # Codes are single use.
        again = await exchange(client, reply["code"])
        assert (again.status_code, again.json()["error"]) == (400, "invalid_grant")

    assert len(mock_google.calls("/token", method="POST")) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "verifier,description",
    [
        ("w" * 43, "Invalid code verifier."),
        ("short", "Invalid code verifier."),
        ("", "Missing code verifier."),
    ],
)
async def test_bad_pkce_verifier(mock_google, verifier, description):
    async with mock_google.client() as client:
        reply = await authorize(client)
        response = await exchange(client, reply["code"], verifier=verifier)
    assert response.status_code == 400
    assert response.json() == {
        "error": "invalid_grant",
        "error_description": description,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides,status,error",
    [
        ({"client_id": "someone-else"}, 401, "invalid_client"),
        ({"redirect_uri": "https://evil.example/cb"}, 400, "redirect_uri_mismatch"),
        ({"response_type": "token"}, 400, "unsupported_response_type"),
        ({"code_challenge_method": "plain"}, 400, "invalid_request"),
        ({"code_challenge": None}, 400, "invalid_request"),
        ({"access_type": "online"}, 400, "invalid_request"),
        ({"access_type": None}, 400, "invalid_request"),
        ({"scope": None}, 400, "invalid_request"),
        ({"scope": "openid made-up-scope"}, 400, "invalid_scope"),
    ],
)
async def test_authorize_validates_request(mock_google, overrides, status, error):
    async with mock_google.client() as client:
        response = await client.get(
            "/o/oauth2/v2/auth", params=authorize_params(**overrides)
        )
    assert response.status_code == status
    assert response.json()["error"] == error


@pytest.mark.asyncio
async def test_exchange_checks_client_secret_and_redirect_uri(mock_google):
    async with mock_google.client() as client:
        reply = await authorize(client)
        bad_secret = await exchange(client, reply["code"], client_secret="wrong")
        assert (bad_secret.status_code, bad_secret.json()["error"]) == (
            401,
            "invalid_client",
        )
        bad_redirect = await exchange(
            client, reply["code"], redirect_uri="http://localhost/other"
        )
        assert bad_redirect.json()["error"] == "redirect_uri_mismatch"
        garbage = await exchange(client, "not-a-code")
        assert garbage.json() == {
            "error": "invalid_grant",
            "error_description": "Malformed auth code.",
        }


@pytest.mark.asyncio
async def test_deny_knob(mock_google):
    mock_google.oauth.deny = True
    async with mock_google.client() as client:
        reply = await authorize(client)
    assert reply == {"error": "access_denied", "state": "state-123"}


@pytest.mark.asyncio
async def test_user_and_partial_scope_knobs(mock_google):
    mock_google.oauth.user = GoogleUser("42", "bob@example.com")
    mock_google.oauth.granted_scopes = {"openid", SCOPE_SHEETS_RO}
    async with mock_google.client() as client:
        body = await connect(client, scope=f"openid email {SCOPE_SHEETS}")
        # Only what was both requested and granted.
        assert body["scope"] == "openid"
        info = await client.get("/v1/userinfo", headers=bearer(body["access_token"]))
    # No email scope granted, so no email.
    assert info.json() == {"sub": "42"}


# --- refresh, rotate, revoke -------------------------------------------------


@pytest.mark.asyncio
async def test_refresh(mock_google):
    async with mock_google.client() as client:
        body = await connect(client)
        response = await refresh(client, body["refresh_token"])
        assert response.status_code == 200
        refreshed = response.json()
        assert refreshed["access_token"] != body["access_token"]
        assert "refresh_token" not in refreshed
        bad = await refresh(client, body["refresh_token"], client_secret="wrong")
        assert bad.json()["error"] == "invalid_client"
        unknown = await refresh(client, "1//unknown")
        assert unknown.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_revoke_then_refresh_is_invalid_grant(mock_google):
    async with mock_google.client() as client:
        body = await connect(client)
        response = await client.post("/revoke", data={"token": body["refresh_token"]})
        assert response.status_code == 200
        assert mock_google.oauth.is_revoked(body["refresh_token"])

        refreshed = await refresh(client, body["refresh_token"])
        assert refreshed.status_code == 400
        assert refreshed.json() == {
            "error": "invalid_grant",
            "error_description": "Token has been expired or revoked.",
        }
        # Access tokens from the grant die with it.
        info = await client.get("/v1/userinfo", headers=bearer(body["access_token"]))
        assert info.status_code == 401
        # Revoking twice is an error, like Google.
        twice = await client.post("/revoke", data={"token": body["refresh_token"]})
        assert twice.json()["error"] == "invalid_token"

    revokes = mock_google.calls("/revoke")
    assert [c.form for c in revokes] == [{"token": body["refresh_token"]}] * 2


@pytest.mark.asyncio
async def test_revoking_access_token_revokes_grant(mock_google):
    async with mock_google.client() as client:
        body = await connect(client)
        await client.post("/revoke", data={"token": body["access_token"]})
        response = await refresh(client, body["refresh_token"])
    assert response.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_revoke_failure_knob(mock_google):
    refresh_token = mock_google.oauth.issue_refresh_token()
    mock_google.faults.fail("/revoke", 500)
    async with mock_google.client() as client:
        failed = await client.post("/revoke", data={"token": refresh_token})
        assert failed.status_code == 500
        assert not mock_google.oauth.is_revoked(refresh_token)
        ok = await client.post("/revoke", data={"token": refresh_token})
        assert ok.status_code == 200
    assert [c.status for c in mock_google.calls("/revoke")] == [500, 200]
    assert mock_google.calls("/revoke")[0].form == {"token": refresh_token}


@pytest.mark.asyncio
async def test_rotate_refresh_tokens_knob(mock_google):
    mock_google.oauth.rotate_refresh_tokens = True
    refresh_token = mock_google.oauth.issue_refresh_token()
    async with mock_google.client() as client:
        response = await refresh(client, refresh_token)
        new_token = response.json()["refresh_token"]
        assert new_token != refresh_token
        old = await refresh(client, refresh_token)
        assert old.json()["error"] == "invalid_grant"
        assert (await refresh(client, new_token)).status_code == 200


@pytest.mark.asyncio
async def test_userinfo_rejects_bad_token(mock_google):
    async with mock_google.client() as client:
        response = await client.get("/v1/userinfo", headers=bearer("ya29.nope"))
    assert response.status_code == 401


# --- service accounts (JWT bearer) -----------------------------------------------


@pytest.mark.asyncio
async def test_service_account_token(mock_google, service_account_keys):
    async with mock_google.client() as client:
        response = await sa_token(client, service_account_keys["test"])
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["scope"] == SCOPE_SHEETS
        assert body["token_type"] == "Bearer"
        # Google's own token URL is an accepted audience too.
        google_aud = await sa_token(
            client,
            service_account_keys["test"],
            aud="https://oauth2.googleapis.com/token",
        )
        assert google_aud.status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name,claims,error,description",
    [
        ("unregistered", {}, "invalid_grant", "Invalid grant: account not found"),
        # Signed with sa-other's key but claiming to be sa-test.
        ("other", {"iss": SA_TEST}, "invalid_grant", "Invalid JWT Signature."),
        (
            "test",
            {"aud": "https://evil.example/token"},
            "invalid_grant",
            "Invalid JWT: Failed audience check.",
        ),
        ("test", {"exp": int(time.time()) + 7200}, "invalid_grant", None),
        ("test", {"scope": ""}, "invalid_scope", None),
    ],
)
async def test_service_account_token_errors(
    mock_google, service_account_keys, name, claims, error, description
):
    async with mock_google.client() as client:
        response = await sa_token(client, service_account_keys[name], **claims)
    assert response.status_code == 400
    assert response.json()["error"] == error
    if description is not None:
        assert response.json()["error_description"] == description


@pytest.mark.asyncio
async def test_service_account_token_500_once(mock_google, service_account_keys):
    async with mock_google.client() as client:
        first = await sa_token(client, service_account_keys["token_500"])
        second = await sa_token(client, service_account_keys["token_500"])
    assert (first.status_code, second.status_code) == (500, 200)


def test_key_material_not_in_repr(service_account_keys):
    key = service_account_keys["test"]
    assert "PRIVATE KEY" in key.key_json()["private_key"]
    assert "PRIVATE" not in repr(key)
    assert "private_key=" not in repr(key)


# --- Sheets ---------------------------------------------------------------------


async def user_token(client, scope=SCOPES):
    return (await connect(client, scope=scope))["access_token"]


@pytest.mark.asyncio
async def test_sheets_read(mock_google):
    async with mock_google.client() as client:
        token = await user_token(client)
        meta = await client.get(
            f"{SHEETS_BASE}/v4/spreadsheets/students",
            params={"fields": "sheets.properties"},
            headers=bearer(token),
        )
        assert [s["properties"]["title"] for s in meta.json()["sheets"]] == [
            "students",
            "assignments",
        ]
        values = await client.get(
            f"{SHEETS_BASE}/v4/spreadsheets/students/values/assignments",
            params={"valueRenderOption": "UNFORMATTED_VALUE"},
            headers=bearer(token),
        )
        assert values.json() == {
            "range": "assignments!A1:Z1000",
            "majorDimension": "ROWS",
            "values": [
                ["id", "title", "max_score"],
                [101, "Essay: Modern Poetry", 100],
                [102, "Lab: Chemical Reactions", 50.5],
            ],
        }
        formatted = await client.get(
            f"{SHEETS_BASE}/v4/spreadsheets/ragged/values/'data'!A1:E5",
            headers=bearer(token),
        )
        assert formatted.json()["values"] == [
            ["name", "", "name", "score"],
            ["alice", "x", "a2", "10"],
            ["bob"],
            [],
            ["carol", "", "", "30", "extra"],
        ]
    meta_call = mock_google.calls(
        "/v4/spreadsheets/students", host="sheets.googleapis.com"
    )[0]
    assert meta_call.query == {"fields": ["sheets.properties"]}


@pytest.mark.asyncio
async def test_sheets_write_create_append_clear(mock_google):
    async with mock_google.client() as client:
        token = await user_token(client)
        created = await client.post(
            f"{SHEETS_BASE}/v4/spreadsheets",
            json={"properties": {"title": "Export"}},
            headers=bearer(token),
        )
        spreadsheet_id = created.json()["spreadsheetId"]
        base = f"{SHEETS_BASE}/v4/spreadsheets/{spreadsheet_id}/values"

        updated = await client.put(
            f"{base}/Sheet1!A1",
            params={"valueInputOption": "RAW"},
            json={"values": [["a", "b"], ["=1+1", 2]]},
            headers=bearer(token),
        )
        assert updated.json()["updatedRange"] == "Sheet1!A1:B2"
        appended = await client.post(
            f"{base}/Sheet1:append",
            params={"valueInputOption": "RAW"},
            json={"values": [["c", 3]]},
            headers=bearer(token),
        )
        assert appended.json()["tableRange"] == "Sheet1!A1:B2"
        assert appended.json()["updates"]["updatedRange"] == "Sheet1!A3:B3"

        read = await client.get(
            f"{base}/Sheet1",
            params={"valueRenderOption": "UNFORMATTED_VALUE"},
            headers=bearer(token),
        )
        # Stored as given: the mock never evaluates formulas.
        assert read.json()["values"] == [["a", "b"], ["=1+1", 2], ["c", 3]]

        cleared = await client.post(f"{base}/Sheet1!A2:B3:clear", headers=bearer(token))
        assert cleared.json()["clearedRange"] == "Sheet1!A2:B3"
        after = await client.get(f"{base}/Sheet1", headers=bearer(token))
        assert after.json()["values"] == [["a", "b"]]

        missing_option = await client.put(
            f"{base}/Sheet1!A1", json={"values": [["x"]]}, headers=bearer(token)
        )
        assert missing_option.status_code == 400

    writes = mock_google.calls(
        f"/v4/spreadsheets/{spreadsheet_id}/values", method="PUT"
    )
    assert writes[0].query["valueInputOption"] == ["RAW"]
    assert writes[0].json == {"values": [["a", "b"], ["=1+1", 2]]}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method,path,scope,status,message",
    [
        (
            "GET",
            "private/values/Sheet1",
            SCOPES,
            403,
            "The caller does not have permission",
        ),
        ("GET", "nope/values/Sheet1", SCOPES, 404, "Requested entity was not found."),
        (
            "PUT",
            "readonly/values/Sheet1!A1?valueInputOption=RAW",
            SCOPES,
            403,
            "The caller does not have permission",
        ),
        (
            "PUT",
            "students/values/students!A1?valueInputOption=RAW",
            f"openid email {SCOPE_SHEETS_RO}",
            403,
            "Request had insufficient authentication scopes.",
        ),
        ("GET", "students/values/nosuchsheet!A1", SCOPES, 400, "Unable to parse range"),
    ],
)
async def test_sheets_errors(mock_google, method, path, scope, status, message):
    async with mock_google.client() as client:
        token = await user_token(client, scope=scope)
        response = await client.request(
            method,
            f"{SHEETS_BASE}/v4/spreadsheets/{path}",
            json={"values": [["x"]]} if method == "PUT" else None,
            headers=bearer(token),
        )
    assert response.status_code == status
    assert response.json()["error"]["message"].startswith(message)


@pytest.mark.asyncio
async def test_sheets_service_account_access(mock_google, service_account_keys):
    async with mock_google.client() as client:
        test = (await sa_token(client, service_account_keys["test"])).json()
        other = (await sa_token(client, service_account_keys["other"])).json()
        url = f"{SHEETS_BASE}/v4/spreadsheets/students/values/students!A1"
        ok = await client.get(url, headers=bearer(test["access_token"]))
        denied = await client.get(url, headers=bearer(other["access_token"]))
    assert ok.json()["values"] == [["id"]]
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_injected_401_then_ok_and_expire_knob(mock_google):
    async with mock_google.client() as client:
        token = await user_token(client)
        mock_google.faults.fail("/v4/spreadsheets/", 401, times=1)
        url = f"{SHEETS_BASE}/v4/spreadsheets/students"
        first = await client.get(url, headers=bearer(token))
        second = await client.get(url, headers=bearer(token))
        assert (first.status_code, second.status_code) == (401, 200)
        assert first.json()["error"]["status"] == "UNAUTHENTICATED"

        mock_google.tokens.expire_all()
        expired = await client.get(url, headers=bearer(token))
        assert expired.status_code == 401
