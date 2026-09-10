# Copyright 2026 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0

"""Support for Vitesy devices."""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, cast

import orjson
from aiohttp import ClientError
from yarl import URL

from .const import (
    _LOGGER,
    API_BASE_URL,
    API_HEADERS,
    APP_CLIENT_ID,
    APP_PROGRAM_TYPE,
    APP_REDIRECT_URI,
    APP_SCOPE,
    AUTH_BASE_URL,
    CSRF_COOKIE,
    DEFAULT_TIMEOUT,
    DEFAULT_TOKEN_TTL,
    LOGIN_URL,
    OAUTH_HEADERS,
    TOKEN_URL,
)
from .exceptions import CannotAuthenticate, CannotConnect, GenericResponseError

if TYPE_CHECKING:
    from aiohttp import ClientSession, ClientTimeout

NONCE_BYTES = 8
VERIFIER_BYTES = 32


@dataclass
class VitesyDevice:
    """A Vitesy device together with its latest cloud data.

    ``data`` is the raw device payload from the ``devices`` endpoint,
    ``measurement`` the most recent measurement (empty when the device has never
    reported), ``maintenance`` is keyed by component (``"filter"``, ``"fridge"``)
    and ``programs`` is the available-program catalogue keyed by program id.
    ``program_id`` is the id of the program currently set on the device.
    """

    device_id: str
    name: str
    model: str
    device_type: str
    firmware_version: str
    connected: bool
    program_id: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    measurement: dict[str, Any] = field(default_factory=dict)
    maintenance: dict[str, Any] = field(default_factory=dict)
    programs: dict[str, dict[str, Any]] = field(default_factory=dict)


class VitesyApi:
    """Client for the Vitesy Hub cloud API.

    ``username`` is the e-mail address of the Vitesy Hub account. The
    ``session`` is provided by the caller, which also owns its lifecycle.
    """

    def __init__(
        self,
        username: str,
        password: str,
        session: ClientSession,
        timeout: ClientTimeout = DEFAULT_TIMEOUT,
    ) -> None:
        """Initialize the API client."""
        self.username = username
        self.password = password
        self.session = session
        self.timeout = timeout

        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.expires_at: float | None = None

    async def login(self) -> None:
        """Run the OAuth2 PKCE flow and store the resulting tokens."""
        _LOGGER.debug("Logging in to Vitesy Hub as %s", self.username)
        verifier = self._generate_verifier()
        code = await self._get_auth_code(self._generate_challenge(verifier))
        await self._exchange_token(code, verifier)
        _LOGGER.debug("Vitesy Hub login successful")

    async def _get_auth_code(self, challenge: str) -> str:
        """Drive the hosted login form and return the authorization code."""
        query = {
            "redirect_uri": APP_REDIRECT_URI,
            "client_id": APP_CLIENT_ID,
            "response_type": "code",
            "state": secrets.token_hex(NONCE_BYTES),
            "nonce": secrets.token_hex(NONCE_BYTES),
            "scope": APP_SCOPE,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        url = URL(LOGIN_URL).with_query(query)

        try:
            async with self.session.request("GET", url, timeout=self.timeout) as resp:
                if resp.status != HTTPStatus.OK:
                    raise CannotAuthenticate(
                        f"Login page request failed: HTTP {resp.status}",
                    )
        except ClientError as err:
            raise CannotConnect(f"Login page request failed: {err}") from err

        cookies = self.session.cookie_jar.filter_cookies(URL(AUTH_BASE_URL))
        if CSRF_COOKIE not in cookies:
            raise CannotAuthenticate("CSRF token not found in login response cookies")

        data = {
            "_csrf": cookies[CSRF_COOKIE].value,
            "username": self.username,
            "password": self.password,
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": str(url),
        }
        try:
            async with self.session.request(
                "POST",
                url,
                data=data,
                headers=headers,
                allow_redirects=False,
                timeout=self.timeout,
            ) as resp:
                location: str = resp.headers.get("Location", "")
        except ClientError as err:
            raise CannotConnect(f"Login request failed: {err}") from err

        if "code=" not in location:
            raise CannotAuthenticate("Login failed: no authorization code returned")
        code: str = location.split("code=")[1].split("&", maxsplit=1)[0]
        return code

    async def _exchange_token(self, code: str, code_verifier: str) -> None:
        """Exchange the authorization code for access and refresh tokens."""
        await self._token_request(
            {
                "grant_type": "authorization_code",
                "client_id": APP_CLIENT_ID,
                "redirect_uri": APP_REDIRECT_URI,
                "code_verifier": code_verifier,
                "code": code,
            },
        )

    async def refresh_access_token(self) -> None:
        """Use the stored refresh token to obtain a fresh access token."""
        if not self.refresh_token:
            raise CannotAuthenticate("No refresh token available; call login() first")
        await self._token_request(
            {
                "grant_type": "refresh_token",
                "client_id": APP_CLIENT_ID,
                "refresh_token": self.refresh_token,
                "scope": APP_SCOPE,
            },
        )

    async def _token_request(self, payload: dict[str, str]) -> None:
        """Post to the token endpoint and store the returned tokens."""
        try:
            async with self.session.request(
                "POST",
                TOKEN_URL,
                data=payload,
                headers=OAUTH_HEADERS,
                timeout=self.timeout,
            ) as resp:
                body = await resp.read()
                status = resp.status
        except ClientError as err:
            raise CannotConnect(f"Token request failed: {err}") from err

        if status != HTTPStatus.OK:
            raise CannotAuthenticate(
                f"Token request failed: HTTP {status}: {body.decode(errors='replace')}",
            )

        data = _decode_json("POST", "oauth2/token", body)
        if not isinstance(data, dict) or "access_token" not in data:
            raise CannotAuthenticate(f"Token response missing access_token: {data}")
        self.access_token = str(data["access_token"])
        self.refresh_token = data.get("refresh_token") or self.refresh_token
        self.expires_at = time.time() + float(data.get("expires_in", DEFAULT_TOKEN_TTL))

    def is_token_expired(self) -> bool:
        """Return whether the current access token has expired."""
        return time.time() >= (self.expires_at or 0)

    async def _auth_headers(self) -> dict[str, str]:
        """Return request headers carrying a valid bearer token."""
        if self.access_token is None or self.is_token_expired():
            if not self.refresh_token:
                raise CannotAuthenticate("Not logged in; call login() first")
            await self.refresh_access_token()
        return {
            **API_HEADERS,
            "Authorization": f"Bearer {self.access_token}",
        }

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> object:
        """Perform an authenticated request against the Vitesy Hub API.

        A ``401`` is retried once after refreshing the access token, matching the
        behaviour of the official app.
        """
        url = URL(f"{API_BASE_URL}/{path}")
        if params:
            url = url.with_query(params)

        refreshed = False
        while True:
            headers = await self._auth_headers()
            _LOGGER.debug("%s %s", method, url)
            try:
                async with self.session.request(
                    method,
                    url,
                    headers=headers,
                    timeout=self.timeout,
                ) as resp:
                    body = await resp.read()
                    status = resp.status
            except ClientError as err:
                raise CannotConnect(f"{method} {path} failed: {err}") from err

            if (
                status == HTTPStatus.UNAUTHORIZED
                and not refreshed
                and self.refresh_token
            ):
                _LOGGER.debug("%s %s returned 401, refreshing token", method, path)
                await self.refresh_access_token()
                refreshed = True
                continue
            break

        if status != HTTPStatus.OK:
            if status == HTTPStatus.UNAUTHORIZED:
                raise CannotAuthenticate(f"{method} {path} returned HTTP 401")
            detail = body.decode(errors="replace")
            raise GenericResponseError(
                f"{method} {path} failed: HTTP {status}: {detail}",
            )

        if not body:
            return {}
        return _decode_json(method, path, body)

    async def _request_list(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Perform a request that is expected to return a JSON array."""
        result = await self._request(method, path, params=params)
        if not isinstance(result, list):
            raise GenericResponseError(f"{method} {path}: expected a JSON array")
        return cast("list[dict[str, Any]]", result)

    async def _request_dict(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Perform a request that is expected to return a JSON object."""
        result = await self._request(method, path, params=params)
        if not isinstance(result, dict):
            raise GenericResponseError(f"{method} {path}: expected a JSON object")
        return cast("dict[str, Any]", result)

    async def get_health(self) -> dict[str, Any]:
        """Return the Vitesy Hub service health status."""
        return await self._request_dict("GET", "health")

    async def get_user(self) -> dict[str, Any]:
        """Return the authenticated user's profile."""
        return await self._request_dict("GET", "users/me")

    async def get_devices(self) -> list[dict[str, Any]]:
        """Return the list of devices registered to the account."""
        return await self._request_list(
            "GET",
            "devices",
            params={
                "user_id": "me",
                "connected_once": "true",
                "expand": "all,-place",
            },
        )

    async def get_device(self, device_id: str) -> dict[str, Any]:
        """Return a single device with all nested data expanded."""
        return await self._request_dict(
            "GET",
            f"devices/{device_id}",
            params={"expand": "all,-place"},
        )

    async def get_measurements(self, device_id: str) -> list[dict[str, Any]]:
        """Return the latest measurements for a device."""
        return await self._request_list(
            "GET",
            "measurements",
            params={"device_id": device_id, "latest": "true"},
        )

    async def get_programs(
        self,
        device_type: str,
        firmware_version: str,
        app_type: str = APP_PROGRAM_TYPE,
    ) -> list[dict[str, Any]]:
        """Return the programs available for a device type and firmware."""
        return await self._request_list(
            "GET",
            "programs",
            params={
                "device_type": device_type,
                "firmware_version": firmware_version,
                "appType": app_type,
            },
        )

    async def get_all_devices(self) -> dict[str, VitesyDevice]:
        """Return every device keyed by id, enriched with its latest cloud data.

        The program catalogue is fetched once per distinct
        ``(device_type, firmware_version)`` pair.
        """
        program_catalogues: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
        devices: dict[str, VitesyDevice] = {}
        for raw in await self.get_devices():
            device_id = str(raw["id"])
            device_type = str(raw.get("type", ""))
            firmware_version = str(raw.get("firmware_version", ""))

            catalogue_key = (device_type, firmware_version)
            known = catalogue_key in program_catalogues
            if device_type and firmware_version and not known:
                program_catalogues[catalogue_key] = {
                    str(program["id"]): program
                    for program in await self.get_programs(
                        device_type,
                        firmware_version,
                    )
                    if "id" in program
                }

            measurements = await self.get_measurements(device_id)
            devices[device_id] = VitesyDevice(
                device_id=device_id,
                name=str(raw.get("name") or device_type or device_id),
                model=str(raw.get("model", "")),
                device_type=device_type,
                firmware_version=firmware_version,
                connected=bool(raw.get("connected", False)),
                program_id=str((raw.get("program") or {}).get("ref", "")),
                data=raw,
                measurement=measurements[0] if measurements else {},
                maintenance=raw.get("maintenance") or {},
                programs=dict(program_catalogues.get(catalogue_key, {})),
            )
        return devices

    @staticmethod
    def _generate_verifier() -> str:
        """Generate a PKCE code verifier."""
        return (
            base64.urlsafe_b64encode(secrets.token_bytes(VERIFIER_BYTES))
            .rstrip(b"=")
            .decode("utf-8")
        )

    @staticmethod
    def _generate_challenge(verifier: str) -> str:
        """Derive the PKCE code challenge from a verifier."""
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("utf-8")


def _decode_json(method: str, path: str, body: bytes) -> object:
    """Decode a JSON response body, raising on malformed payloads."""
    try:
        result: object = orjson.loads(body)
    except orjson.JSONDecodeError as err:
        raise GenericResponseError(
            f"{method} {path}: invalid JSON response: {body.decode(errors='replace')}",
        ) from err
    return result
