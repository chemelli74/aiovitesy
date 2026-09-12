# Copyright 2026 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the async Vitesy Hub API client."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import time
from http.cookies import SimpleCookie
from typing import TYPE_CHECKING, Any, cast

import pytest
from aiohttp import ClientError
from yarl import URL

from aiovitesy.api import VitesyApi, VitesyCertificate, VitesyDevice, VitesyModeStatus
from aiovitesy.const import AUTH_BASE_URL, CSRF_COOKIE
from aiovitesy.exceptions import (
    CannotAuthenticate,
    CannotConnect,
    GenericResponseError,
)
from tests.conftest import FakeResponse, FakeSession

if TYPE_CHECKING:
    from collections.abc import Callable

Route = tuple[str, str, object]

VERIFIER_DECODED_BYTES = 32
ATTEMPTS_WITH_RETRY = 2


def make_session(*routes: Route) -> FakeSession:
    """Build a FakeSession that dispatches requests by method and URL substring."""

    def handler(method: str, url: URL, kwargs: dict[str, object]) -> FakeResponse:
        for r_method, r_sub, r_resp in routes:
            if r_method != method or r_sub not in str(url):
                continue
            if isinstance(r_resp, Exception):
                raise r_resp
            if isinstance(r_resp, FakeResponse):
                return r_resp
            builder = cast("Callable[[dict[str, object]], FakeResponse]", r_resp)
            return builder(kwargs)
        msg = f"no route for {method} {url}"
        raise AssertionError(msg)

    return FakeSession(handler)


def make_api(session: FakeSession) -> VitesyApi:
    """Create a client bound to the given fake session."""
    return VitesyApi("user@example.com", "s3cr3t", cast("Any", session))


def logged_in_api(session: FakeSession) -> VitesyApi:
    """Return a client that already holds a valid, non-expired token."""
    api = make_api(session)
    api.access_token = "access-1"
    api.refresh_token = "refresh-1"
    api.expires_at = time.time() + 3600
    return api


def seed_csrf_cookie(session: FakeSession, value: str = "csrf-123") -> None:
    """Populate the session cookie jar with the login CSRF cookie."""
    session.cookie_jar.update_cookies(
        SimpleCookie({CSRF_COOKIE: value}),
        URL(AUTH_BASE_URL),
    )


LOGIN_SUCCESS_ROUTES: tuple[Route, ...] = (
    ("GET", "auth.vitesy.com/login", FakeResponse(status=200)),
    (
        "POST",
        "auth.vitesy.com/login",
        FakeResponse(
            status=302,
            headers={
                "Location": "hub.vitesy.com:/oauth2redirect?code=auth-code-xyz&state=x"
            },
        ),
    ),
    (
        "POST",
        "auth.vitesy.com/oauth2/token",
        FakeResponse.json_response(
            {
                "access_token": "access-1",
                "refresh_token": "refresh-1",
                "expires_in": 1800,
            },
        ),
    ),
)


def test_generate_verifier_is_high_entropy_url_safe() -> None:
    """The PKCE verifier decodes to 32 random bytes and has no padding."""
    verifier = VitesyApi._generate_verifier()  # noqa: SLF001
    assert "=" not in verifier
    assert len(base64.urlsafe_b64decode(verifier + "===")) == VERIFIER_DECODED_BYTES
    assert verifier != VitesyApi._generate_verifier()  # noqa: SLF001


def test_generate_challenge_is_sha256_of_verifier() -> None:
    """The PKCE challenge is the unpadded url-safe base64 SHA-256 of the verifier."""
    digest = hashlib.sha256(b"verifier-value").digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert VitesyApi._generate_challenge("verifier-value") == expected  # noqa: SLF001


def test_login_success_stores_tokens() -> None:
    """A full login populates the access/refresh tokens and expiry."""
    session = make_session(*LOGIN_SUCCESS_ROUTES)
    api = make_api(session)
    seed_csrf_cookie(session)

    before = time.time()
    asyncio.run(api.login())

    assert api.access_token == "access-1"
    assert api.refresh_token == "refresh-1"
    assert api.expires_at is not None
    assert before + 1800 <= api.expires_at <= time.time() + 1800

    token_call = next(c for c in session.requests if "oauth2/token" in str(c[1]))
    payload = cast("dict[str, str]", token_call[2]["data"])
    assert payload["grant_type"] == "authorization_code"
    assert payload["code"] == "auth-code-xyz"
    assert payload["code_verifier"]

    login_post = next(
        c
        for c in session.requests
        if c[0] == "POST" and "auth.vitesy.com/login" in str(c[1])
    )
    login_data = cast("dict[str, str]", login_post[2]["data"])
    assert login_data["_csrf"] == "csrf-123"
    assert login_data["username"] == "user@example.com"


def test_login_missing_csrf_cookie() -> None:
    """Login aborts when the hosted page does not set the CSRF cookie."""
    session = make_session(("GET", "auth.vitesy.com/login", FakeResponse(status=200)))
    api = make_api(session)

    with pytest.raises(CannotAuthenticate, match="CSRF token"):
        asyncio.run(api.login())


def test_login_without_authorization_code() -> None:
    """Login fails when the credentials POST does not redirect with a code."""
    session = make_session(
        ("GET", "auth.vitesy.com/login", FakeResponse(status=200)),
        (
            "POST",
            "auth.vitesy.com/login",
            FakeResponse(
                status=302, headers={"Location": "hub.vitesy.com:/oauth2redirect"}
            ),
        ),
    )
    api = make_api(session)
    seed_csrf_cookie(session)

    with pytest.raises(CannotAuthenticate, match="authorization code"):
        asyncio.run(api.login())


def test_login_page_http_error() -> None:
    """A non-200 from the login page raises CannotAuthenticate."""
    session = make_session(("GET", "auth.vitesy.com/login", FakeResponse(status=503)))
    api = make_api(session)

    with pytest.raises(CannotAuthenticate, match="HTTP 503"):
        asyncio.run(api.login())


def test_login_page_connection_error() -> None:
    """A transport error while loading the login page raises CannotConnect."""
    session = make_session(
        ("GET", "auth.vitesy.com/login", ClientError("boom")),
    )
    api = make_api(session)

    with pytest.raises(CannotConnect):
        asyncio.run(api.login())


def test_token_request_http_error() -> None:
    """A failed token exchange raises CannotAuthenticate with the status."""
    session = make_session(
        ("GET", "auth.vitesy.com/login", FakeResponse(status=200)),
        (
            "POST",
            "auth.vitesy.com/login",
            FakeResponse(
                status=302,
                headers={"Location": "hub.vitesy.com:/oauth2redirect?code=abc"},
            ),
        ),
        (
            "POST",
            "auth.vitesy.com/oauth2/token",
            FakeResponse(status=400, body=b"invalid_grant"),
        ),
    )
    api = make_api(session)
    seed_csrf_cookie(session)

    with pytest.raises(CannotAuthenticate, match="HTTP 400"):
        asyncio.run(api.login())


def test_login_credentials_post_connection_error() -> None:
    """A transport error on the credentials POST raises CannotConnect."""
    session = make_session(
        ("GET", "auth.vitesy.com/login", FakeResponse(status=200)),
        ("POST", "auth.vitesy.com/login", ClientError("reset")),
    )
    api = make_api(session)
    seed_csrf_cookie(session)

    with pytest.raises(CannotConnect):
        asyncio.run(api.login())


def test_token_request_connection_error() -> None:
    """A transport error on the token endpoint raises CannotConnect."""
    session = make_session(
        ("GET", "auth.vitesy.com/login", FakeResponse(status=200)),
        (
            "POST",
            "auth.vitesy.com/login",
            FakeResponse(
                status=302,
                headers={"Location": "hub.vitesy.com:/oauth2redirect?code=abc"},
            ),
        ),
        ("POST", "auth.vitesy.com/oauth2/token", ClientError("reset")),
    )
    api = make_api(session)
    seed_csrf_cookie(session)

    with pytest.raises(CannotConnect):
        asyncio.run(api.login())


def test_token_response_without_access_token() -> None:
    """A token payload lacking access_token raises CannotAuthenticate."""
    session = make_session(
        ("GET", "auth.vitesy.com/login", FakeResponse(status=200)),
        (
            "POST",
            "auth.vitesy.com/login",
            FakeResponse(
                status=302,
                headers={"Location": "hub.vitesy.com:/oauth2redirect?code=abc"},
            ),
        ),
        (
            "POST",
            "auth.vitesy.com/oauth2/token",
            FakeResponse.json_response({"token_type": "Bearer"}),
        ),
    )
    api = make_api(session)
    seed_csrf_cookie(session)

    with pytest.raises(CannotAuthenticate, match="missing access_token"):
        asyncio.run(api.login())


def test_request_dict_rejects_wrong_shape() -> None:
    """A JSON array where an object is expected raises GenericResponseError."""
    session = make_session(
        (
            "GET",
            "v1.api.vitesyhub.com/devices/AA",
            FakeResponse.json_response([1, 2, 3]),
        ),
    )
    api = logged_in_api(session)

    with pytest.raises(GenericResponseError, match="expected a JSON object"):
        asyncio.run(api.get_device("AA"))


@pytest.mark.parametrize(
    ("expires_at", "expected"),
    [
        pytest.param(None, True, id="no-expiry"),
        pytest.param(time.time() - 10, True, id="past"),
        pytest.param(time.time() + 3600, False, id="future"),
    ],
)
def test_is_token_expired(expires_at: float | None, expected: bool) -> None:
    """Token expiry is derived from the stored expiry timestamp."""
    api = make_api(make_session())
    api.expires_at = expires_at
    assert api.is_token_expired() is expected


def test_refresh_access_token_without_refresh_token() -> None:
    """Refreshing without a stored refresh token raises CannotAuthenticate."""
    api = make_api(make_session())

    with pytest.raises(CannotAuthenticate, match="refresh token"):
        asyncio.run(api.refresh_access_token())


def test_request_refreshes_expired_token() -> None:
    """An expired access token is refreshed transparently before a request."""
    session = make_session(
        (
            "POST",
            "auth.vitesy.com/oauth2/token",
            FakeResponse.json_response(
                {"access_token": "access-2", "expires_in": 3600},
            ),
        ),
        ("GET", "v1.api.vitesyhub.com/devices", FakeResponse.json_response([])),
    )
    api = logged_in_api(session)
    api.expires_at = time.time() - 5

    asyncio.run(api.get_devices())

    assert api.access_token == "access-2"
    assert api.refresh_token == "refresh-1"
    devices_call = next(c for c in session.requests if "/devices" in str(c[1]))
    headers = cast("dict[str, str]", devices_call[2]["headers"])
    assert headers["Authorization"] == "Bearer access-2"


def test_request_requires_login() -> None:
    """Calling an API method before login raises CannotAuthenticate."""
    api = make_api(make_session())

    with pytest.raises(CannotAuthenticate, match="Not logged in"):
        asyncio.run(api.get_devices())


def test_request_refreshes_when_only_refresh_token_is_known() -> None:
    """A client restored from just a refresh token obtains an access token."""
    session = make_session(
        (
            "POST",
            "auth.vitesy.com/oauth2/token",
            FakeResponse.json_response(
                {"access_token": "access-9", "expires_in": 3600},
            ),
        ),
        ("GET", "v1.api.vitesyhub.com/health", FakeResponse.json_response({"ok": 1})),
    )
    api = make_api(session)
    api.refresh_token = "refresh-1"

    asyncio.run(api.get_health())

    assert api.access_token == "access-9"


def test_get_devices_builds_expected_request() -> None:
    """get_devices targets the devices endpoint with the documented query."""
    session = make_session(
        (
            "GET",
            "v1.api.vitesyhub.com/devices",
            FakeResponse.json_response([{"id": "AA:BB"}]),
        ),
    )
    api = logged_in_api(session)

    result = asyncio.run(api.get_devices())

    assert result == [{"id": "AA:BB"}]
    method, url, kwargs = session.requests[0]
    assert method == "GET"
    assert url.path == "/devices"
    assert url.query["user_id"] == "me"
    assert url.query["connected_once"] == "true"
    assert url.query["expand"] == "all,-place"
    headers = cast("dict[str, str]", kwargs["headers"])
    assert headers["Authorization"] == "Bearer access-1"
    assert headers["User-Agent"].startswith("VitesyHub/")
    assert "Content-Type" not in headers


def test_get_measurements_builds_expected_request() -> None:
    """get_measurements passes the device id and latest flag as query params."""
    session = make_session(
        ("GET", "v1.api.vitesyhub.com/measurements", FakeResponse.json_response([])),
    )
    api = logged_in_api(session)

    asyncio.run(api.get_measurements("AA:BB:CC"))

    _, url, _ = session.requests[0]
    assert url.path == "/measurements"
    assert url.query["device_id"] == "AA:BB:CC"
    assert url.query["latest"] == "true"


def test_get_programs_builds_expected_request() -> None:
    """get_programs passes the device type, firmware version and app type."""
    session = make_session(
        ("GET", "v1.api.vitesyhub.com/programs?", FakeResponse.json_response([])),
    )
    api = logged_in_api(session)

    asyncio.run(api.get_programs("SHELFY-R1", "1.2.3"))

    _, url, _ = session.requests[0]
    assert url.path == "/programs"
    assert url.query["device_type"] == "SHELFY-R1"
    assert url.query["firmware_version"] == "1.2.3"
    assert url.query["appType"] == "DEFAULT"


def test_get_health_and_user_endpoints() -> None:
    """get_health and get_user target the documented read endpoints."""
    session = make_session(
        (
            "GET",
            "v1.api.vitesyhub.com/health",
            FakeResponse.json_response({"suspended": False, "message": "OK"}),
        ),
        (
            "GET",
            "v1.api.vitesyhub.com/users/me",
            FakeResponse.json_response({"id": "u1", "email": "a@b.c"}),
        ),
    )
    api = logged_in_api(session)

    assert asyncio.run(api.get_health()) == {"suspended": False, "message": "OK"}
    assert asyncio.run(api.get_user())["id"] == "u1"
    assert session.requests[0][1].path == "/health"
    assert session.requests[1][1].path == "/users/me"


def test_get_device_builds_expected_request() -> None:
    """get_device fetches a single device with nested data expanded."""
    session = make_session(
        (
            "GET",
            "v1.api.vitesyhub.com/devices/80:65:99:34:F9:B4",
            FakeResponse.json_response({"id": "80:65:99:34:F9:B4"}),
        ),
    )
    api = logged_in_api(session)

    result = asyncio.run(api.get_device("80:65:99:34:F9:B4"))

    assert result == {"id": "80:65:99:34:F9:B4"}
    _, url, _ = session.requests[0]
    assert url.path == "/devices/80:65:99:34:F9:B4"
    assert url.query["expand"] == "all,-place"


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        pytest.param(403, GenericResponseError, id="forbidden"),
        pytest.param(500, GenericResponseError, id="server-error"),
    ],
)
def test_request_error_status(status: int, expected: type[Exception]) -> None:
    """Non-200 responses map to the matching library exception."""
    session = make_session(
        ("GET", "v1.api.vitesyhub.com/devices", FakeResponse(status=status)),
    )
    api = logged_in_api(session)

    with pytest.raises(expected):
        asyncio.run(api.get_devices())


def test_request_retries_once_on_401_then_succeeds() -> None:
    """A 401 triggers a token refresh and a single retry, matching the app."""
    calls: list[int] = []

    def devices(_kwargs: dict[str, object]) -> FakeResponse:
        calls.append(1)
        if len(calls) == 1:
            return FakeResponse(
                status=401,
                body=b'{"error":{"status":401,"message":"Expired token"}}',
            )
        return FakeResponse.json_response([{"id": "AA:BB"}])

    session = make_session(
        (
            "POST",
            "auth.vitesy.com/oauth2/token",
            FakeResponse.json_response(
                {"access_token": "access-2", "expires_in": 3600},
            ),
        ),
        ("GET", "v1.api.vitesyhub.com/devices", devices),
    )
    api = logged_in_api(session)

    assert asyncio.run(api.get_devices()) == [{"id": "AA:BB"}]
    assert len(calls) == ATTEMPTS_WITH_RETRY
    assert api.access_token == "access-2"
    retry = session.requests[-1]
    assert cast("dict[str, str]", retry[2]["headers"])["Authorization"] == (
        "Bearer access-2"
    )


def test_request_raises_when_401_persists_after_refresh() -> None:
    """A 401 that survives the refresh+retry raises CannotAuthenticate."""
    session = make_session(
        (
            "POST",
            "auth.vitesy.com/oauth2/token",
            FakeResponse.json_response(
                {"access_token": "access-2", "expires_in": 3600},
            ),
        ),
        ("GET", "v1.api.vitesyhub.com/devices", FakeResponse(status=401)),
    )
    api = logged_in_api(session)

    with pytest.raises(CannotAuthenticate):
        asyncio.run(api.get_devices())
    device_calls = [c for c in session.requests if c[1].path == "/devices"]
    assert len(device_calls) == ATTEMPTS_WITH_RETRY


def test_request_connection_error() -> None:
    """Transport failures during an API call raise CannotConnect."""
    session = make_session(
        ("GET", "v1.api.vitesyhub.com/devices", ClientError("down")),
    )
    api = logged_in_api(session)

    with pytest.raises(CannotConnect):
        asyncio.run(api.get_devices())


def test_request_invalid_json() -> None:
    """A malformed JSON body raises GenericResponseError."""
    session = make_session(
        (
            "GET",
            "v1.api.vitesyhub.com/devices",
            FakeResponse(status=200, body=b"not json"),
        ),
    )
    api = logged_in_api(session)

    with pytest.raises(GenericResponseError, match="invalid JSON"):
        asyncio.run(api.get_devices())


def test_request_empty_body_returns_empty_dict() -> None:
    """An empty 200 body is treated as an empty JSON object."""
    session = make_session(
        (
            "GET",
            "v1.api.vitesyhub.com/devices/AA",
            FakeResponse(status=200, body=b""),
        ),
    )
    api = logged_in_api(session)

    assert asyncio.run(api.get_device("AA")) == {}


def test_request_list_rejects_wrong_shape() -> None:
    """A JSON object where a list is expected raises GenericResponseError."""
    session = make_session(
        (
            "GET",
            "v1.api.vitesyhub.com/devices",
            FakeResponse.json_response({"unexpected": "object"}),
        ),
    )
    api = logged_in_api(session)

    with pytest.raises(GenericResponseError, match="expected a JSON array"):
        asyncio.run(api.get_devices())


def test_get_all_devices_aggregates_related_data() -> None:
    """get_all_devices reads maintenance/program from the device payload."""
    session = make_session(
        (
            "GET",
            "v1.api.vitesyhub.com/devices?",
            FakeResponse.json_response(
                [
                    {
                        "id": "80:65:99:34:F9:B4",
                        "name": "Shelly",
                        "type": "SHELFY-R1",
                        "model": "SH02AA02",
                        "firmware_version": "1.2.3",
                        "connected": True,
                        "program": {"ref": "eco-s1", "data": {"id": "eco-s1"}},
                        "maintenance": {
                            "filter": {"due_date": "2026-08-02T06:45:07.623Z"},
                        },
                        "battery": {"level": 27, "charging": False},
                    },
                ],
            ),
        ),
        (
            "GET",
            "v1.api.vitesyhub.com/measurements",
            FakeResponse.json_response([{"score": 0.9}, {"score": 0.5}]),
        ),
        (
            "GET",
            "v1.api.vitesyhub.com/programs?",
            FakeResponse.json_response(
                [
                    {"id": "eco-s1", "name": "Eco", "preset": {"mode": "eco"}},
                    {"id": "shelf-s1", "name": "Crisper", "preset": {"mode": "shelf"}},
                ],
            ),
        ),
    )
    api = logged_in_api(session)

    devices = asyncio.run(api.get_all_devices())

    assert list(devices) == ["80:65:99:34:F9:B4"]
    device = devices["80:65:99:34:F9:B4"]
    assert isinstance(device, VitesyDevice)
    assert device.name == "Shelly"
    assert device.model == "SH02AA02"
    assert device.device_type == "SHELFY-R1"
    assert device.firmware_version == "1.2.3"
    assert device.connected is True
    assert device.program_id == "eco-s1"
    assert device.data["battery"] == {"level": 27, "charging": False}
    assert device.measurement == {"score": 0.9}
    assert device.maintenance == {"filter": {"due_date": "2026-08-02T06:45:07.623Z"}}
    assert device.programs == {
        "eco-s1": {"id": "eco-s1", "name": "Eco", "preset": {"mode": "eco"}},
        "shelf-s1": {"id": "shelf-s1", "name": "Crisper", "preset": {"mode": "shelf"}},
    }
    assert not any(c[1].path.endswith("/maintenance") for c in session.requests)


def test_get_all_devices_handles_missing_data() -> None:
    """Programs are skipped without type/firmware and absent nested data is empty."""
    session = make_session(
        (
            "GET",
            "v1.api.vitesyhub.com/devices?",
            FakeResponse.json_response([{"id": "AA:BB:CC"}]),
        ),
        (
            "GET",
            "v1.api.vitesyhub.com/measurements",
            FakeResponse.json_response([]),
        ),
    )
    api = logged_in_api(session)

    device = asyncio.run(api.get_all_devices())["AA:BB:CC"]

    assert device.programs == {}
    assert device.measurement == {}
    assert device.maintenance == {}
    assert device.program_id == ""
    assert device.name == "AA:BB:CC"
    assert not any("/programs" in str(c[1]) for c in session.requests)


def test_get_all_devices_fetches_program_catalogue_once_per_model() -> None:
    """Devices sharing a type/firmware reuse a single GET /programs call."""
    session = make_session(
        (
            "GET",
            "v1.api.vitesyhub.com/devices?",
            FakeResponse.json_response(
                [
                    {"id": "AA:01", "type": "SHELFY-R1", "firmware_version": "1.2.3"},
                    {"id": "AA:02", "type": "SHELFY-R1", "firmware_version": "1.2.3"},
                    {"id": "AA:03", "type": "NATEDE-R1", "firmware_version": "2.0.0"},
                ],
            ),
        ),
        (
            "GET",
            "v1.api.vitesyhub.com/measurements",
            FakeResponse.json_response([]),
        ),
        (
            "GET",
            "v1.api.vitesyhub.com/programs?",
            FakeResponse.json_response([{"id": "eco-s1"}]),
        ),
    )
    api = logged_in_api(session)

    devices = asyncio.run(api.get_all_devices())

    program_device_types = [
        c[1].query["device_type"] for c in session.requests if c[1].path == "/programs"
    ]
    assert program_device_types == ["SHELFY-R1", "NATEDE-R1"]
    assert devices["AA:01"].programs == devices["AA:02"].programs
    assert devices["AA:01"].programs is not devices["AA:02"].programs


def test_get_certificate_builds_expected_request_and_caches() -> None:
    """get_certificate fetches the account's AWS IoT cert once and caches it."""
    session = make_session(
        (
            "GET",
            "v1.api.vitesyhub.com/users/me",
            FakeResponse.json_response({"id": "user-1"}),
        ),
        (
            "GET",
            "v1.api.vitesyhub.com/certificates",
            FakeResponse.json_response(
                [
                    {
                        "certificate": "cert-pem",
                        "private_key": "key-pem",
                        "root_certificate": "root-pem",
                    },
                ],
            ),
        ),
    )
    api = logged_in_api(session)

    certificate = asyncio.run(api.get_certificate())
    second = asyncio.run(api.get_certificate())

    assert certificate.certificate == "cert-pem"
    assert certificate.private_key == "key-pem"
    assert certificate.root_certificate == "root-pem"
    assert second is certificate

    cert_call = next(c for c in session.requests if c[1].path == "/certificates")
    assert cert_call[1].query["subject_id"] == "user-1"
    assert cert_call[1].query["format"] == "p12"
    assert sum(1 for c in session.requests if c[1].path == "/certificates") == 1
    assert sum(1 for c in session.requests if c[1].path == "/users/me") == 1


def test_get_certificate_rejects_user_without_id() -> None:
    """get_certificate raises when /users/me has no 'id' to key the cert on."""
    session = make_session(
        ("GET", "v1.api.vitesyhub.com/users/me", FakeResponse.json_response({})),
    )
    api = logged_in_api(session)

    with pytest.raises(GenericResponseError, match="missing 'id'"):
        asyncio.run(api.get_certificate())


def test_get_certificate_rejects_empty_response() -> None:
    """get_certificate raises when the certificates endpoint returns nothing."""
    session = make_session(
        (
            "GET",
            "v1.api.vitesyhub.com/users/me",
            FakeResponse.json_response({"id": "user-1"}),
        ),
        ("GET", "v1.api.vitesyhub.com/certificates", FakeResponse.json_response([])),
    )
    api = logged_in_api(session)

    with pytest.raises(GenericResponseError, match="no certificate"):
        asyncio.run(api.get_certificate())


def test_set_mode_fetches_certificate_and_publishes_shadow_update(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """set_mode fetches the account certificate then delegates to the shadow client."""
    session = make_session(
        (
            "GET",
            "v1.api.vitesyhub.com/users/me",
            FakeResponse.json_response({"id": "user-1"}),
        ),
        (
            "GET",
            "v1.api.vitesyhub.com/certificates",
            FakeResponse.json_response(
                [{"certificate": "c", "private_key": "k", "root_certificate": "r"}],
            ),
        ),
    )
    api = logged_in_api(session)

    calls: list[tuple[VitesyCertificate, str, str]] = []

    async def fake_set_shadow_mode(
        certificate: VitesyCertificate,
        device_id: str,
        mode: str,
    ) -> None:
        calls.append((certificate, device_id, mode))

    monkeypatch.setattr("aiovitesy.api.set_shadow_mode", fake_set_shadow_mode)

    asyncio.run(api.set_mode("AA:BB:CC", "shelf"))

    assert len(calls) == 1
    certificate, device_id, mode = calls[0]
    assert certificate.certificate == "c"
    assert device_id == "AA:BB:CC"
    assert mode == "shelf"


def _certificate_session() -> FakeSession:
    """Build a session that satisfies get_certificate's own requests."""
    return make_session(
        (
            "GET",
            "v1.api.vitesyhub.com/users/me",
            FakeResponse.json_response({"id": "user-1"}),
        ),
        (
            "GET",
            "v1.api.vitesyhub.com/certificates",
            FakeResponse.json_response(
                [{"certificate": "c", "private_key": "k", "root_certificate": "r"}],
            ),
        ),
    )


def test_get_mode_status_reports_pending_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A device that hasn't caught up to its desired mode reports pending."""
    api = logged_in_api(_certificate_session())

    async def fake_get_shadow(
        _certificate: VitesyCertificate,
        _device_id: str,
    ) -> dict[str, object]:
        return {"state": {"desired": {"mode": "eco"}, "reported": {"mode": "shelf"}}}

    monkeypatch.setattr("aiovitesy.api.get_shadow", fake_get_shadow)

    status = asyncio.run(api.get_mode_status("AA:BB:CC"))

    assert status == VitesyModeStatus(
        desired_mode="eco",
        current_mode="shelf",
        pending=True,
    )


def test_get_mode_status_reports_applied_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A device that has caught up to its desired mode reports not pending."""
    api = logged_in_api(_certificate_session())

    async def fake_get_shadow(
        _certificate: VitesyCertificate,
        _device_id: str,
    ) -> dict[str, object]:
        return {"state": {"desired": {"mode": "eco"}, "reported": {"mode": "eco"}}}

    monkeypatch.setattr("aiovitesy.api.get_shadow", fake_get_shadow)

    status = asyncio.run(api.get_mode_status("AA:BB:CC"))

    assert status == VitesyModeStatus(
        desired_mode="eco",
        current_mode="eco",
        pending=False,
    )


def test_get_mode_status_handles_device_that_never_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A device shadow with no reported state yet is not treated as pending."""
    api = logged_in_api(_certificate_session())

    async def fake_get_shadow(
        _certificate: VitesyCertificate,
        _device_id: str,
    ) -> dict[str, object]:
        return {"state": {}}

    monkeypatch.setattr("aiovitesy.api.get_shadow", fake_get_shadow)

    status = asyncio.run(api.get_mode_status("AA:BB:CC"))

    assert status == VitesyModeStatus(
        desired_mode=None, current_mode=None, pending=False
    )
