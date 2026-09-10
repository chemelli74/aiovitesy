# Copyright 2026 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0

"""Base tests for aiovitesy."""

from aiovitesy import __version__
from aiovitesy.api import VitesyApi, VitesyDevice
from aiovitesy.exceptions import (
    CannotAuthenticate,
    CannotConnect,
    GenericResponseError,
    VitesyError,
)


def test_objects_can_be_imported() -> None:
    """Verify objects exist."""
    assert isinstance(__version__, str)
    assert type(CannotAuthenticate)
    assert type(CannotConnect)
    assert type(GenericResponseError)
    assert type(VitesyError)
    assert type(VitesyApi)
    assert type(VitesyDevice)
