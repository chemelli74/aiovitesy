# Copyright 2026 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0

"""Base import tests for aiovitesy."""

from aiovitesy import __version__
from aiovitesy.api import VitesyApi, VitesyDevice
from aiovitesy.exceptions import (
    CannotAuthenticate,
    CannotConnect,
    GenericResponseError,
    VitesyError,
)


def test_objects_can_be_imported() -> None:
    """Verify the public objects are importable."""
    assert isinstance(__version__, str)
    for obj in (
        CannotAuthenticate,
        CannotConnect,
        GenericResponseError,
        VitesyError,
        VitesyApi,
        VitesyDevice,
    ):
        assert obj is not None

    assert issubclass(CannotAuthenticate, VitesyError)
    assert issubclass(CannotConnect, VitesyError)
    assert issubclass(GenericResponseError, VitesyError)
