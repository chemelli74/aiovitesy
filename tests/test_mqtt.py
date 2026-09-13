# Copyright 2026 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the AWS IoT device shadow client."""

from __future__ import annotations

import asyncio
import shutil
import ssl
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, Self

import orjson
import pytest

from aiovitesy.api import VitesyCertificate
from aiovitesy.exceptions import GenericResponseError
from aiovitesy.mqtt import (
    _build_ssl_context,
    _build_ssl_context_async,
    get_shadow,
    set_shadow_mode,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from pathlib import Path

DEVICE_ID = "80:65:99:34:F9:B4"
SHADOW_TOPIC = f"$aws/things/{DEVICE_ID}/shadow"


def _client_token_of(payload: bytes | None) -> str:
    """Extract the clientToken a publish() call actually sent."""
    body: Any = orjson.loads(payload) if payload else {}
    token = body.get("clientToken")
    assert isinstance(token, str)
    return token


@dataclass
class FakeMessage:
    """Minimal stand-in for an ``aiomqtt.Message``."""

    topic: str
    payload: bytes


@dataclass
class FakeMqttClient:
    """Minimal async stand-in for ``aiomqtt.Client``.

    Instances record their subscriptions/publishes so tests can assert on
    them after ``set_shadow_mode`` returns; ``queued_messages`` is replayed by
    ``.messages`` and then blocks forever, matching a real subscription that
    never sees another message. Since a real ``clientToken`` is generated
    internally (unknown to the test in advance), ``response_builder`` lets a
    test compute the reply from what was actually published.
    """

    queued_messages: ClassVar[list[FakeMessage]] = []
    created: ClassVar[list[FakeMqttClient]] = []
    hang_after_messages: ClassVar[bool] = True
    response_builder: ClassVar[
        Callable[[str, bytes | None], list[FakeMessage]] | None
    ] = None

    kwargs: dict[str, object] = field(default_factory=dict)
    subscriptions: list[str] = field(default_factory=list)
    published: list[tuple[str, bytes | None]] = field(default_factory=list)

    def __init__(self, **kwargs: object) -> None:
        """Record constructor kwargs and register this instance."""
        self.kwargs = kwargs
        self.subscriptions = []
        self.published = []
        FakeMqttClient.created.append(self)

    async def __aenter__(self) -> Self:
        """Enter the async context, returning self."""
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        """Exit the async context without suppressing exceptions."""
        return False

    async def subscribe(self, topic: str, *_args: object, **_kwargs: object) -> None:
        """Record a subscription request."""
        self.subscriptions.append(topic)

    async def publish(
        self,
        topic: str,
        payload: bytes | None = None,
        *_args: object,
        **_kwargs: object,
    ) -> None:
        """Record a publish request and queue its response, if configured."""
        self.published.append((topic, payload))
        if FakeMqttClient.response_builder is not None:
            FakeMqttClient.queued_messages = FakeMqttClient.response_builder(
                topic,
                payload,
            )

    @property
    def messages(self) -> AsyncIterator[FakeMessage]:
        """Replay the queued messages, then hang like a live subscription."""

        async def _stream() -> AsyncIterator[FakeMessage]:
            for message in FakeMqttClient.queued_messages:
                yield message
            if FakeMqttClient.hang_after_messages:
                await asyncio.Event().wait()

        return _stream()


@pytest.fixture
def fake_mqtt(monkeypatch: pytest.MonkeyPatch) -> type[FakeMqttClient]:
    """Patch ``aiomqtt.Client`` with the fake and reset its recorded state."""
    FakeMqttClient.queued_messages = []
    FakeMqttClient.created = []
    FakeMqttClient.hang_after_messages = True
    FakeMqttClient.response_builder = None
    monkeypatch.setattr("aiovitesy.mqtt.aiomqtt.Client", FakeMqttClient)
    return FakeMqttClient


@pytest.fixture(scope="module")
def self_signed_certificate(
    tmp_path_factory: pytest.TempPathFactory,
) -> VitesyCertificate:
    """Generate a throwaway self-signed cert/key pair for TLS-context tests."""
    directory: Path = tmp_path_factory.mktemp("certs")
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    openssl = shutil.which("openssl")
    assert openssl is not None
    subprocess.run(  # noqa: S603
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=aiovitesy-test",
        ],
        check=True,
        capture_output=True,
    )
    certificate = cert_path.read_text()
    return VitesyCertificate(
        certificate=certificate,
        private_key=key_path.read_text(),
        root_certificate=certificate,
    )


def test_build_ssl_context_loads_certificate_and_key(
    self_signed_certificate: VitesyCertificate,
) -> None:
    """A cert/key/root PEM bundle loads into a working client-auth context."""
    context = _build_ssl_context(self_signed_certificate)
    assert isinstance(context, ssl.SSLContext)


def test_build_ssl_context_async_runs_off_the_event_loop(
    self_signed_certificate: VitesyCertificate,
) -> None:
    """The async wrapper offloads the blocking file I/O to a worker thread."""
    context = asyncio.run(_build_ssl_context_async(self_signed_certificate))
    assert isinstance(context, ssl.SSLContext)


def test_set_shadow_mode_publishes_and_confirms_on_accepted(
    fake_mqtt: type[FakeMqttClient],
    self_signed_certificate: VitesyCertificate,
) -> None:
    """A shadow update succeeds once the broker echoes it back as accepted."""

    def build_response(_topic: str, payload: bytes | None) -> list[FakeMessage]:
        token = _client_token_of(payload)
        return [
            FakeMessage(
                topic=f"{SHADOW_TOPIC}/update/accepted",
                payload=orjson.dumps({"clientToken": token}),
            ),
        ]

    fake_mqtt.response_builder = build_response

    asyncio.run(set_shadow_mode(self_signed_certificate, DEVICE_ID, "eco"))

    client = fake_mqtt.created[0]
    assert client.subscriptions == [
        f"{SHADOW_TOPIC}/update/accepted",
        f"{SHADOW_TOPIC}/update/rejected",
    ]
    topic, payload = client.published[0]
    assert topic == f"{SHADOW_TOPIC}/update"
    assert payload is not None
    body: Any = orjson.loads(payload)
    assert body["state"] == {"desired": {"mode": "eco"}}
    assert isinstance(body["clientToken"], str)


def test_set_shadow_mode_raises_on_rejected(
    fake_mqtt: type[FakeMqttClient],
    self_signed_certificate: VitesyCertificate,
) -> None:
    """A rejected shadow update raises with the broker's payload."""

    def build_response(_topic: str, payload: bytes | None) -> list[FakeMessage]:
        token = _client_token_of(payload)
        return [
            FakeMessage(
                topic=f"{SHADOW_TOPIC}/update/rejected",
                payload=orjson.dumps(
                    {"clientToken": token, "code": 400, "message": "bad mode"},
                ),
            ),
        ]

    fake_mqtt.response_builder = build_response

    with pytest.raises(GenericResponseError, match="rejected"):
        asyncio.run(set_shadow_mode(self_signed_certificate, DEVICE_ID, "not-a-mode"))


def test_set_shadow_mode_ignores_response_with_mismatched_client_token(
    fake_mqtt: type[FakeMqttClient],
    self_signed_certificate: VitesyCertificate,
) -> None:
    """A reply carrying someone else's clientToken is ignored, not accepted."""

    def build_response(_topic: str, payload: bytes | None) -> list[FakeMessage]:
        token = _client_token_of(payload)
        return [
            FakeMessage(
                topic=f"{SHADOW_TOPIC}/update/accepted",
                payload=orjson.dumps({"clientToken": "someone-elses-token"}),
            ),
            FakeMessage(
                topic=f"{SHADOW_TOPIC}/update/accepted",
                payload=orjson.dumps({"clientToken": token}),
            ),
        ]

    fake_mqtt.response_builder = build_response

    asyncio.run(set_shadow_mode(self_signed_certificate, DEVICE_ID, "eco"))


@pytest.mark.usefixtures("fake_mqtt")
def test_set_shadow_mode_times_out_without_a_response(
    self_signed_certificate: VitesyCertificate,
) -> None:
    """A shadow update that gets no accepted/rejected response times out."""
    with pytest.raises(TimeoutError):
        asyncio.run(
            set_shadow_mode(self_signed_certificate, DEVICE_ID, "eco", timeout=0.05),
        )


def test_get_shadow_returns_parsed_document(
    fake_mqtt: type[FakeMqttClient],
    self_signed_certificate: VitesyCertificate,
) -> None:
    """get_shadow requests the shadow and returns the parsed accepted body."""
    shadow_state = {
        "state": {"desired": {"mode": "eco"}, "reported": {"mode": "shelf"}},
        "version": 15150,
    }

    def build_response(_topic: str, payload: bytes | None) -> list[FakeMessage]:
        token = _client_token_of(payload)
        return [
            FakeMessage(
                topic=f"{SHADOW_TOPIC}/get/accepted",
                payload=orjson.dumps({**shadow_state, "clientToken": token}),
            ),
        ]

    fake_mqtt.response_builder = build_response

    result = asyncio.run(get_shadow(self_signed_certificate, DEVICE_ID))

    assert result["state"] == shadow_state["state"]
    assert result["version"] == shadow_state["version"]
    assert isinstance(result["clientToken"], str)
    client = fake_mqtt.created[0]
    assert client.subscriptions == [
        f"{SHADOW_TOPIC}/get/accepted",
        f"{SHADOW_TOPIC}/get/rejected",
    ]
    topic, payload = client.published[0]
    assert topic == f"{SHADOW_TOPIC}/get"
    assert payload is not None
    assert isinstance(orjson.loads(payload)["clientToken"], str)


def test_get_shadow_raises_on_rejected(
    fake_mqtt: type[FakeMqttClient],
    self_signed_certificate: VitesyCertificate,
) -> None:
    """A rejected shadow get raises with the broker's payload."""

    def build_response(_topic: str, payload: bytes | None) -> list[FakeMessage]:
        token = _client_token_of(payload)
        return [
            FakeMessage(
                topic=f"{SHADOW_TOPIC}/get/rejected",
                payload=orjson.dumps(
                    {"clientToken": token, "code": 404, "message": "No shadow exists"},
                ),
            ),
        ]

    fake_mqtt.response_builder = build_response

    with pytest.raises(GenericResponseError, match="rejected"):
        asyncio.run(get_shadow(self_signed_certificate, DEVICE_ID))


def test_get_shadow_ignores_response_with_mismatched_client_token(
    fake_mqtt: type[FakeMqttClient],
    self_signed_certificate: VitesyCertificate,
) -> None:
    """A reply carrying someone else's clientToken is ignored, not accepted."""

    def build_response(_topic: str, payload: bytes | None) -> list[FakeMessage]:
        token = _client_token_of(payload)
        return [
            FakeMessage(
                topic=f"{SHADOW_TOPIC}/get/accepted",
                payload=orjson.dumps(
                    {"clientToken": "someone-elses-token", "state": {"reported": {}}},
                ),
            ),
            FakeMessage(
                topic=f"{SHADOW_TOPIC}/get/accepted",
                payload=orjson.dumps(
                    {"clientToken": token, "state": {"reported": {"mode": "eco"}}},
                ),
            ),
        ]

    fake_mqtt.response_builder = build_response

    result = asyncio.run(get_shadow(self_signed_certificate, DEVICE_ID))

    assert result["state"]["reported"]["mode"] == "eco"


def test_get_shadow_ignores_unparsable_message_on_response_topic(
    fake_mqtt: type[FakeMqttClient],
    self_signed_certificate: VitesyCertificate,
) -> None:
    """A non-JSON payload on the accepted topic is skipped, not raised on."""

    def build_response(_topic: str, payload: bytes | None) -> list[FakeMessage]:
        token = _client_token_of(payload)
        return [
            FakeMessage(
                topic=f"{SHADOW_TOPIC}/get/accepted",
                payload=b"not json",
            ),
            FakeMessage(
                topic=f"{SHADOW_TOPIC}/get/accepted",
                payload=orjson.dumps(
                    {"clientToken": token, "state": {"reported": {"mode": "eco"}}},
                ),
            ),
        ]

    fake_mqtt.response_builder = build_response

    result = asyncio.run(get_shadow(self_signed_certificate, DEVICE_ID))

    assert result["state"]["reported"]["mode"] == "eco"


@pytest.mark.usefixtures("fake_mqtt")
def test_get_shadow_times_out_without_a_response(
    self_signed_certificate: VitesyCertificate,
) -> None:
    """A shadow get that gets no accepted/rejected response times out."""
    with pytest.raises(TimeoutError):
        asyncio.run(get_shadow(self_signed_certificate, DEVICE_ID, timeout=0.05))


def test_get_shadow_ignores_message_on_an_unrelated_topic(
    fake_mqtt: type[FakeMqttClient],
    self_signed_certificate: VitesyCertificate,
) -> None:
    """A message on a topic that isn't the accepted/rejected pair is skipped."""

    def build_response(_topic: str, payload: bytes | None) -> list[FakeMessage]:
        token = _client_token_of(payload)
        return [
            FakeMessage(
                topic=f"{SHADOW_TOPIC}/update/delta",
                payload=orjson.dumps({"state": {"mode": "eco"}}),
            ),
            FakeMessage(
                topic=f"{SHADOW_TOPIC}/get/accepted",
                payload=orjson.dumps(
                    {"clientToken": token, "state": {"reported": {"mode": "eco"}}},
                ),
            ),
        ]

    fake_mqtt.response_builder = build_response

    result = asyncio.run(get_shadow(self_signed_certificate, DEVICE_ID))

    assert result["state"]["reported"]["mode"] == "eco"


def test_get_shadow_raises_when_message_stream_ends_unmatched(
    fake_mqtt: type[FakeMqttClient],
    self_signed_certificate: VitesyCertificate,
) -> None:
    """If the broker's message stream ends with no matching reply, raise."""
    fake_mqtt.hang_after_messages = False

    with pytest.raises(GenericResponseError, match="No response received"):
        asyncio.run(get_shadow(self_signed_certificate, DEVICE_ID))
