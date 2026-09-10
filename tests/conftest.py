# Copyright 2026 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0

"""Shared pytest fixtures and lightweight aiohttp fakes for aiovitesy."""

from __future__ import annotations

from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import TYPE_CHECKING, Self, cast

import orjson
import pytest
from yarl import URL

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

    RequestHandler = Callable[[str, URL, dict[str, object]], "FakeResponse"]


@dataclass
class FakeResponse:
    """Minimal async stand-in for ``aiohttp.ClientResponse``."""

    status: int = 200
    body: bytes = b"{}"
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def json_response(cls, payload: object, status: int = 200) -> FakeResponse:
        """Build a response carrying a JSON-encoded body."""
        return cls(status=status, body=orjson.dumps(payload))

    async def __aenter__(self) -> Self:
        """Enter the async context, returning self."""
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> bool:
        """Exit the async context without suppressing exceptions."""
        return False

    async def read(self) -> bytes:
        """Return the raw response body."""
        return self.body

    async def text(self) -> str:
        """Return the response body decoded as text."""
        return self.body.decode()


def _default_handler(
    _method: str, _url: URL, _kwargs: dict[str, object]
) -> FakeResponse:
    return FakeResponse()


class FakeCookieJar:
    """Loop-free stand-in for ``aiohttp.CookieJar`` covering the calls we use."""

    def __init__(self) -> None:
        """Set up an empty cookie store."""
        self._cookies: SimpleCookie = SimpleCookie()

    def update_cookies(self, cookies: object, _response_url: URL | None = None) -> None:
        """Merge the given cookies into the store."""
        self._cookies.update(cast("SimpleCookie", cookies))

    def filter_cookies(self, _request_url: URL | None = None) -> SimpleCookie:
        """Return every stored cookie regardless of the request URL."""
        return self._cookies


class FakeSession:
    """Minimal async stand-in for ``aiohttp.ClientSession``."""

    def __init__(self, handler: RequestHandler | None = None) -> None:
        """Store the request handler and set up an empty cookie jar."""
        self._handler = handler or _default_handler
        self.cookie_jar = FakeCookieJar()
        self.requests: list[tuple[str, URL, dict[str, object]]] = []

    def request(
        self,
        method: str,
        url: str | URL,
        **kwargs: object,
    ) -> FakeResponse:
        """Record the call and return the handler's response."""
        parsed = URL(url)
        self.requests.append((method, parsed, kwargs))
        return self._handler(method, parsed, kwargs)


@pytest.fixture
def username() -> str:
    """Provide a deterministic account e-mail."""
    return "user@example.com"


@pytest.fixture
def password() -> str:
    """Provide a deterministic account password."""
    return "s3cr3t"
