# Copyright 2026 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0

"""Support for Vitesy devices."""

from dataclasses import dataclass, field
from typing import Any

from aiohttp import ClientSession

from .const import _LOGGER, DEFAULT_TIMEOUT


@dataclass
class VitesyDevice:
    """Representation of a Vitesy device."""

    device_id: str
    name: str
    model: str
    data: dict[str, Any] = field(default_factory=dict)


class VitesyApi:
    """Client for a Vitesy device."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        session: ClientSession,
    ) -> None:
        """Initialize the API client."""
        self.host = host
        self.username = username
        self.password = password
        self.session = session
        self.timeout = DEFAULT_TIMEOUT

    async def login(self) -> bool:
        """Authenticate against the device."""
        _LOGGER.debug("Login to %s", self.host)
        raise NotImplementedError

    async def get_devices(self) -> dict[str, VitesyDevice]:
        """Return the devices exposed by the account or hub."""
        raise NotImplementedError

    async def close(self) -> None:
        """Release any resources held by the client."""
