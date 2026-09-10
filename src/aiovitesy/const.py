# Copyright 2026 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0

"""Constants for Vitesy devices."""

import logging

from aiohttp import ClientTimeout

_LOGGER = logging.getLogger(__package__)

DEFAULT_TIMEOUT = ClientTimeout(10)
DEFAULT_TOKEN_TTL = 3600

AUTH_BASE_URL = "https://auth.vitesy.com"
API_BASE_URL = "https://v1.api.vitesyhub.com"

LOGIN_URL = f"{AUTH_BASE_URL}/login"
TOKEN_URL = f"{AUTH_BASE_URL}/oauth2/token"

CSRF_COOKIE = "XSRF-TOKEN"

# Vitesy Hub mobile app identity (v6.0.22)
APP_CLIENT_ID = "3jvr7icm60hbbkffbui9j15e9m"
APP_REDIRECT_URI = "hub.vitesy.com:/oauth2redirect"
APP_SCOPE = "openid email profile aws.cognito.signin.user.admin API/*:*"
APP_USER_AGENT = "VitesyHub/6.0.22 (build:443; os:iOS 26.6.2; value:iPhone)"
APP_PROGRAM_TYPE = "DEFAULT"

OAUTH_HEADERS = {
    "Accept": "application/json",
    "Accept-Charset": "UTF-8",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
}
API_HEADERS = {
    "Accept": "application/json",
    "Accept-Charset": "UTF-8",
    "User-Agent": APP_USER_AGENT,
}
