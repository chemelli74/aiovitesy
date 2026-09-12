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
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import aiomqtt
import orjson

from .const import IOT_ENDPOINT, IOT_PORT, SHADOW_TIMEOUT
from .exceptions import GenericResponseError

if TYPE_CHECKING:
    from .api import VitesyCertificate


def _build_ssl_context(certificate: VitesyCertificate) -> ssl.SSLContext:
    """Build a mutual-TLS context from an in-memory PEM certificate bundle.

    This does blocking filesystem I/O (a temp dir, several file writes/reads)
    and must be run off the event loop; see :func:`_build_ssl_context_async`.
    """
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


async def _build_ssl_context_async(certificate: VitesyCertificate) -> ssl.SSLContext:
    """Build the mutual-TLS context off the event loop in a worker thread."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _build_ssl_context, certificate)


@dataclass(frozen=True)
class _ShadowRequest:
    """Identifies one in-flight shadow request awaiting its broker reply."""

    accepted_topic: str
    rejected_topic: str
    client_token: str
    description: str


async def _wait_for_shadow_response(
    client: aiomqtt.Client,
    request: _ShadowRequest,
    *,
    timeout: float,
) -> bytes:
    """Wait for the broker's accepted/rejected reply to a shadow request.

    Shadow response topics are shared by every subscriber, so a concurrent
    call for the same device would otherwise see this call's own request
    answered by a *different* call's response. Each reply is only accepted
    once its echoed ``clientToken`` matches this request's; anything else
    (including a differently-shaped or unparsable payload) is ignored.
    """
    async with asyncio.timeout(timeout):
        async for message in client.messages:
            topic_str = str(message.topic)
            if topic_str not in (request.accepted_topic, request.rejected_topic):
                continue
            payload = bytes(message.payload)
            try:
                body: Any = orjson.loads(payload)
            except orjson.JSONDecodeError:
                continue
            if (
                not isinstance(body, dict)
                or body.get("clientToken") != request.client_token
            ):
                continue
            if topic_str == request.rejected_topic:
                raise GenericResponseError(
                    f"AWS IoT rejected {request.description}: {payload!r}",
                )
            return payload
    raise GenericResponseError(f"No response received for {request.description}")


async def get_shadow(
    certificate: VitesyCertificate,
    device_id: str,
    *,
    timeout: float = SHADOW_TIMEOUT,
) -> dict[str, Any]:
    """Return a device's current AWS IoT device shadow document."""
    ssl_context = await _build_ssl_context_async(certificate)
    topic = f"$aws/things/{device_id}/shadow"
    client_token = secrets.token_hex(8)
    async with aiomqtt.Client(
        hostname=IOT_ENDPOINT,
        port=IOT_PORT,
        tls_context=ssl_context,
        identifier=f"aiovitesy-{secrets.token_hex(4)}",
    ) as client:
        await client.subscribe(f"{topic}/get/accepted")
        await client.subscribe(f"{topic}/get/rejected")
        await client.publish(
            f"{topic}/get",
            payload=orjson.dumps({"clientToken": client_token}),
        )
        payload = await _wait_for_shadow_response(
            client,
            _ShadowRequest(
                accepted_topic=f"{topic}/get/accepted",
                rejected_topic=f"{topic}/get/rejected",
                client_token=client_token,
                description=f"shadow get for {device_id}",
            ),
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
    ssl_context = await _build_ssl_context_async(certificate)
    topic = f"$aws/things/{device_id}/shadow"
    client_token = secrets.token_hex(8)
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
            payload=orjson.dumps(
                {"state": {"desired": {"mode": mode}}, "clientToken": client_token},
            ),
        )
        await _wait_for_shadow_response(
            client,
            _ShadowRequest(
                accepted_topic=f"{topic}/update/accepted",
                rejected_topic=f"{topic}/update/rejected",
                client_token=client_token,
                description=f"shadow update for {device_id}",
            ),
            timeout=timeout,
        )
