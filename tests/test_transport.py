"""Tests for ebicsclient.transport: HTTPS POST and its error mapping.

The network call is monkeypatched, so these run offline.
"""

import ssl
import urllib.error
import urllib.request
from typing import Any

import pytest

from ebicsclient import transport
from ebicsclient.errors import Retryability, TransportError


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *args: Any) -> bool:
        return False

    def read(self) -> bytes:
        return self._body


def test_rejects_non_https_endpoint() -> None:
    with pytest.raises(TransportError):
        transport.Transport("http://ebicsweb.example.com/ebicsweb")


def test_ssl_context_enforces_tls_1_2_floor() -> None:
    context = transport._build_ssl_context()
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_ssl_context_loads_the_certifi_bundle_when_available() -> None:
    pytest.importorskip("certifi")
    # With certifi installed, the context ends up trusting some CAs even on a build whose
    # system store is empty — the fallback loaded them.
    context = transport._build_ssl_context()
    assert context.get_ca_certs()


def test_certifi_trust_is_skipped_when_certifi_is_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import = builtins.__import__

    def _no_certifi(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "certifi":
            raise ImportError("certifi is not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_certifi)
    # Must not raise when certifi cannot be imported — the system store is used as-is.
    context = transport._build_ssl_context()
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_post_returns_the_response_body(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *a, **k: _FakeResponse(b"<ebicsResponse/>")
    )
    client = transport.Transport("https://ebicsweb.example.com/ebicsweb")
    assert client.post(b"<ebicsRequest/>") == b"<ebicsResponse/>"


def test_5xx_is_transient(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*args: Any, **kwargs: Any) -> None:
        raise urllib.error.HTTPError("https://x", 503, "unavailable", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    client = transport.Transport("https://ebicsweb.example.com/ebicsweb")
    with pytest.raises(TransportError) as caught:
        client.post(b"<ebicsRequest/>")
    assert caught.value.retryability is Retryability.TRANSIENT


def test_4xx_is_permanent(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*args: Any, **kwargs: Any) -> None:
        raise urllib.error.HTTPError("https://x", 403, "forbidden", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    client = transport.Transport("https://ebicsweb.example.com/ebicsweb")
    with pytest.raises(TransportError) as caught:
        client.post(b"<ebicsRequest/>")
    assert caught.value.retryability is Retryability.PERMANENT


def test_timeout_is_transient(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*args: Any, **kwargs: Any) -> None:
        raise TimeoutError("timed out")

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    client = transport.Transport("https://ebicsweb.example.com/ebicsweb")
    with pytest.raises(TransportError) as caught:
        client.post(b"<ebicsRequest/>")
    assert caught.value.retryability is Retryability.TRANSIENT
