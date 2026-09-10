# Copyright 2026 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0

"""aiovitesy library exceptions."""

from __future__ import annotations


class VitesyError(Exception):
    """Base class for aiovitesy errors."""


class CannotConnect(VitesyError):
    """Exception raised when connection fails."""


class CannotAuthenticate(VitesyError):
    """Exception raised when credentials are rejected or a token is missing."""


class GenericResponseError(VitesyError):
    """Exception raised when a request returns an unexpected response."""
