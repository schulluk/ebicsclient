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


class _FakeOpener:
    """Stands in for the transport's urllib opener: returns a response or raises."""

    def __init__(self, response: _FakeResponse | None = None, error: Exception | None = None):
        self._response = response
        self._error = error

    def open(self, request: urllib.request.Request, timeout: float) -> _FakeResponse:
        if self._error is not None:
            raise self._error
        assert self._response is not None
        return self._response


def _transport_with(opener: _FakeOpener) -> transport.Transport:
    client = transport.Transport("https://ebicsweb.example.com/ebicsweb")
    client._opener = opener  # type: ignore[assignment]
    return client


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


def test_post_returns_the_response_body() -> None:
    client = _transport_with(_FakeOpener(response=_FakeResponse(b"<ebicsResponse/>")))
    assert client.post(b"<ebicsRequest/>") == b"<ebicsResponse/>"


def _http_error(code: int, reason: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://x", code, reason, {}, None)  # type: ignore[arg-type]


def test_5xx_is_transient() -> None:
    client = _transport_with(_FakeOpener(error=_http_error(503, "unavailable")))
    with pytest.raises(TransportError) as caught:
        client.post(b"<ebicsRequest/>")
    assert caught.value.retryability is Retryability.TRANSIENT


def test_4xx_is_permanent() -> None:
    client = _transport_with(_FakeOpener(error=_http_error(403, "forbidden")))
    with pytest.raises(TransportError) as caught:
        client.post(b"<ebicsRequest/>")
    assert caught.value.retryability is Retryability.PERMANENT


def test_timeout_is_transient() -> None:
    client = _transport_with(_FakeOpener(error=TimeoutError("timed out")))
    with pytest.raises(TransportError) as caught:
        client.post(b"<ebicsRequest/>")
    assert caught.value.retryability is Retryability.TRANSIENT


def test_a_redirect_fails_closed_as_permanent() -> None:
    # urllib would silently follow a 302 (turning the POST into a GET); the transport
    # refuses redirects, so a redirecting endpoint is a hard, explicit failure.
    client = _transport_with(_FakeOpener(error=_http_error(302, "found")))
    with pytest.raises(TransportError) as caught:
        client.post(b"<ebicsRequest/>")
    assert caught.value.retryability is Retryability.PERMANENT
    assert "redirect" in str(caught.value)


def test_the_opener_refuses_redirects() -> None:
    # The handler must answer every redirect with None, which makes urllib raise.
    handler = transport._RedirectRefusedHandler()
    request = urllib.request.Request("https://ebicsweb.example.com/ebicsweb")
    assert (
        handler.redirect_request(request, None, 302, "found", {}, "https://elsewhere") is None
    )
