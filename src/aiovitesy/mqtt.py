# Copyright 2026 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0

"""AWS IoT device shadow client for Vitesy devices.

Vitesy devices are controlled by publishing to their AWS IoT Core "classic"
device shadow over MQTT, authenticated with a per-account client certificate
(see :meth:`aiovitesy.api.VitesyApi.get_certificate`). This bypasses the
``v1.api.vitesyhub.com`` REST API entirely.
"""

from __future__ import annotations

import asyncio
import secrets
import ssl
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import aiomqtt
import orjson

from .const import IOT_ENDPOINT, IOT_PORT, SHADOW_TIMEOUT
from .exceptions import GenericResponseError

if TYPE_CHECKING:
    from .api import VitesyCertificate


def _build_ssl_context(certificate: VitesyCertificate) -> ssl.SSLContext:
    """Build a mutual-TLS context from an in-memory PEM certificate bundle."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        cert_path = tmp / "cert.pem"
        key_path = tmp / "key.pem"
        ca_path = tmp / "ca.pem"
        cert_path.write_text(certificate.certificate)
        key_path.write_text(certificate.private_key)
        ca_path.write_text(certificate.root_certificate)
        context.load_verify_locations(cafile=str(ca_path))
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return context


async def _wait_for_shadow_response(
    client: aiomqtt.Client,
    *,
    accepted_topic: str,
    rejected_topic: str,
    description: str,
    timeout: float,
) -> bytes:
    """Wait for the broker's accepted/rejected reply to a shadow request."""
    async with asyncio.timeout(timeout):
        async for message in client.messages:
            topic_str = str(message.topic)
            if topic_str == rejected_topic:
                raise GenericResponseError(
                    f"AWS IoT rejected {description}: {message.payload!r}",
                )
            if topic_str == accepted_topic:
                return message.payload
    raise GenericResponseError(f"No response received for {description}")


async def get_shadow(
    certificate: VitesyCertificate,
    device_id: str,
    *,
    timeout: float = SHADOW_TIMEOUT,
) -> dict[str, Any]:
    """Return a device's current AWS IoT device shadow document."""
    ssl_context = _build_ssl_context(certificate)
    topic = f"$aws/things/{device_id}/shadow"
    async with aiomqtt.Client(
        hostname=IOT_ENDPOINT,
        port=IOT_PORT,
        tls_context=ssl_context,
        identifier=f"aiovitesy-{secrets.token_hex(4)}",
    ) as client:
        await client.subscribe(f"{topic}/get/accepted")
        await client.subscribe(f"{topic}/get/rejected")
        await client.publish(f"{topic}/get", payload=b"")
        payload = await _wait_for_shadow_response(
            client,
            accepted_topic=f"{topic}/get/accepted",
            rejected_topic=f"{topic}/get/rejected",
            description=f"shadow get for {device_id}",
            timeout=timeout,
        )
    result: Any = orjson.loads(payload)
    return cast("dict[str, Any]", result)


async def set_shadow_mode(
    certificate: VitesyCertificate,
    device_id: str,
    mode: str,
    *,
    timeout: float = SHADOW_TIMEOUT,
) -> None:
    """Set a device's operating mode by updating its AWS IoT device shadow.

    ``mode`` is the raw shadow value (for Shelfy: ``"eco"``, ``"shelf"`` or
    ``"boost"``), not a program id from the ``programs`` REST endpoint.
    """
    ssl_context = _build_ssl_context(certificate)
    topic = f"$aws/things/{device_id}/shadow"
    async with aiomqtt.Client(
        hostname=IOT_ENDPOINT,
        port=IOT_PORT,
        tls_context=ssl_context,
        identifier=f"aiovitesy-{secrets.token_hex(4)}",
    ) as client:
        await client.subscribe(f"{topic}/update/accepted")
        await client.subscribe(f"{topic}/update/rejected")
        await client.publish(
            f"{topic}/update",
            payload=orjson.dumps({"state": {"desired": {"mode": mode}}}),
        )
        await _wait_for_shadow_response(
            client,
            accepted_topic=f"{topic}/update/accepted",
            rejected_topic=f"{topic}/update/rejected",
            description=f"shadow update for {device_id}",
            timeout=timeout,
        )
