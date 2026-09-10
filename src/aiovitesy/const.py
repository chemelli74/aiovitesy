# Copyright 2026 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0

"""Constants for Vitesy devices."""

import logging

from aiohttp import ClientTimeout

_LOGGER = logging.getLogger(__package__)

DEFAULT_TIMEOUT = ClientTimeout(10)
