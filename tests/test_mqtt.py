# Copyright 2026 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the AWS IoT MQTT client."""

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
    from collections.abc import AsyncIterator, Callable, Coroutine
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


@dataclass(frozen=True)
class IotRequest:
    """A public AWS IoT request function and the topic operation it uses."""

    operation: str
    send: Callable[..., Coroutine[Any, Any, object]]


GET_REQUEST = IotRequest(
    operation="get",
    send=lambda certificate, **kwargs: get_shadow(certificate, DEVICE_ID, **kwargs),
)
UPDATE_REQUEST = IotRequest(
    operation="update",
    send=lambda certificate, **kwargs: set_shadow_mode(
        certificate, DEVICE_ID, "eco", **kwargs
    ),
)
IOT_REQUESTS = [
    pytest.param(GET_REQUEST, id="get_shadow"),
    pytest.param(UPDATE_REQUEST, id="set_shadow_mode"),
]


def _reply(iot_request: IotRequest, outcome: str, body: dict[str, Any]) -> FakeMessage:
    """Build a broker reply on the request's accepted/rejected topic."""
    return FakeMessage(
        topic=f"{SHADOW_TOPIC}/{iot_request.operation}/{outcome}",
        payload=orjson.dumps(body),
    )


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(_build_ssl_context, id="sync"),
        pytest.param(
            lambda certificate: asyncio.run(_build_ssl_context_async(certificate)),
            id="executor",
        ),
    ],
)
def test_build_ssl_context_loads_certificate_and_key(
    self_signed_certificate: VitesyCertificate,
    build: Callable[[VitesyCertificate], ssl.SSLContext],
) -> None:
    """A cert/key/root PEM bundle loads into a client-auth context."""
    assert isinstance(build(self_signed_certificate), ssl.SSLContext)


@pytest.mark.parametrize(
    ("iot_request", "expected_body"),
    [
        pytest.param(GET_REQUEST, {}, id="get_shadow"),
        pytest.param(
            UPDATE_REQUEST,
            {"state": {"desired": {"mode": "eco"}}},
            id="set_shadow_mode",
        ),
    ],
)
def test_request_publishes_and_completes_on_accepted(
    fake_mqtt: type[FakeMqttClient],
    self_signed_certificate: VitesyCertificate,
    iot_request: IotRequest,
    expected_body: dict[str, Any],
) -> None:
    """A request subscribes to its replies, publishes, and completes on accepted."""
    fake_mqtt.response_builder = lambda _topic, payload: [
        _reply(iot_request, "accepted", {"clientToken": _client_token_of(payload)}),
    ]

    asyncio.run(iot_request.send(self_signed_certificate))

    client = fake_mqtt.created[0]
    assert client.subscriptions == [
        f"{SHADOW_TOPIC}/{iot_request.operation}/accepted",
        f"{SHADOW_TOPIC}/{iot_request.operation}/rejected",
    ]
    topic, payload = client.published[0]
    assert topic == f"{SHADOW_TOPIC}/{iot_request.operation}"
    body: Any = orjson.loads(payload or b"{}")
    assert isinstance(body.pop("clientToken"), str)
    assert body == expected_body


def test_get_shadow_returns_parsed_document(
    fake_mqtt: type[FakeMqttClient],
    self_signed_certificate: VitesyCertificate,
) -> None:
    """get_shadow returns the parsed accepted body."""
    document = {
        "state": {"desired": {"mode": "eco"}, "reported": {"mode": "shelf"}},
        "version": 15150,
    }
    fake_mqtt.response_builder = lambda _topic, payload: [
        _reply(
            GET_REQUEST,
            "accepted",
            {**document, "clientToken": _client_token_of(payload)},
        ),
    ]

    result = asyncio.run(get_shadow(self_signed_certificate, DEVICE_ID))

    assert isinstance(result.pop("clientToken"), str)
    assert result == document


@pytest.mark.parametrize("iot_request", IOT_REQUESTS)
def test_request_raises_on_rejected(
    fake_mqtt: type[FakeMqttClient],
    self_signed_certificate: VitesyCertificate,
    iot_request: IotRequest,
) -> None:
    """A rejected request raises with the broker's payload."""
    fake_mqtt.response_builder = lambda _topic, payload: [
        _reply(
            iot_request,
            "rejected",
            {"clientToken": _client_token_of(payload), "code": 400, "message": "bad"},
        ),
    ]

    with pytest.raises(GenericResponseError, match="rejected"):
        asyncio.run(iot_request.send(self_signed_certificate))


@pytest.mark.parametrize("iot_request", IOT_REQUESTS)
@pytest.mark.parametrize(
    "noise",
    [
        pytest.param(
            lambda iot_request: _reply(
                iot_request, "accepted", {"clientToken": "someone-elses-token"}
            ),
            id="mismatched-client-token",
        ),
        pytest.param(
            lambda iot_request: FakeMessage(
                topic=f"{SHADOW_TOPIC}/{iot_request.operation}/accepted",
                payload=b"not json",
            ),
            id="unparsable-message",
        ),
        pytest.param(
            lambda _iot_request: FakeMessage(
                topic=f"{SHADOW_TOPIC}/update/delta",
                payload=orjson.dumps({"state": {"mode": "eco"}}),
            ),
            id="unrelated-topic",
        ),
    ],
)
def test_request_ignores_noise_before_the_matching_reply(
    fake_mqtt: type[FakeMqttClient],
    self_signed_certificate: VitesyCertificate,
    iot_request: IotRequest,
    noise: Callable[[IotRequest], FakeMessage],
) -> None:
    """A mismatched token, unparsable payload or unrelated topic is skipped."""
    fake_mqtt.response_builder = lambda _topic, payload: [
        noise(iot_request),
        _reply(iot_request, "accepted", {"clientToken": _client_token_of(payload)}),
    ]

    asyncio.run(iot_request.send(self_signed_certificate))


@pytest.mark.usefixtures("fake_mqtt")
@pytest.mark.parametrize("iot_request", IOT_REQUESTS)
def test_request_times_out_without_a_reply(
    self_signed_certificate: VitesyCertificate,
    iot_request: IotRequest,
) -> None:
    """A request that gets no accepted/rejected reply times out."""
    with pytest.raises(TimeoutError):
        asyncio.run(iot_request.send(self_signed_certificate, timeout=0.05))


@pytest.mark.parametrize("iot_request", IOT_REQUESTS)
def test_request_raises_when_message_stream_ends_unmatched(
    fake_mqtt: type[FakeMqttClient],
    self_signed_certificate: VitesyCertificate,
    iot_request: IotRequest,
) -> None:
    """If the broker's message stream ends with no matching reply, raise."""
    fake_mqtt.hang_after_messages = False

    with pytest.raises(GenericResponseError, match="No response received"):
        asyncio.run(iot_request.send(self_signed_certificate))
