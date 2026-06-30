"""HTTPS transport for EBICS requests.

EBICS security lives in the request payload (signed and encrypted XML), so the
transport only needs a single server-authenticated HTTPS POST — no sessions, cookies,
or redirects. Built on the standard library (``urllib`` + ``ssl``); TLS 1.2 is enforced
as the floor and the server certificate is verified.
"""

import logging
import ssl
import urllib.error
import urllib.request

from ebicsclient.errors import Retryability, TransportError

logger = logging.getLogger(__name__)

_CONTENT_TYPE = "text/xml; charset=UTF-8"
_DEFAULT_TIMEOUT_SECONDS = 30.0
_TRANSIENT_STATUS = frozenset({408, 429})


class Transport:
    """Posts EBICS request bodies to a bank endpoint over HTTPS."""

    def __init__(self, url: str, *, timeout: float = _DEFAULT_TIMEOUT_SECONDS) -> None:
        """Configure the transport for one bank endpoint.

        Args:
            url: The bank's EBICS HTTPS endpoint.
            timeout: Per-request timeout in seconds.

        Raises:
            TransportError: the URL is not an HTTPS URL.
        """
        if not url.lower().startswith("https://"):
            raise TransportError(f"EBICS endpoint must be an https:// URL, got {url!r}")
        self._url = url
        self._timeout = timeout
        self._ssl_context = _build_ssl_context()

    def post(self, body: bytes) -> bytes:
        """Post an EBICS request body and return the raw response bytes.

        Args:
            body: The serialised XML request.

        Returns:
            The raw response body. (EBICS returns HTTP 200 even for protocol-level
            errors, which the response carries inside the XML — so this only fails on
            transport problems, not EBICS return codes.)

        Raises:
            TransportError: the exchange could not be completed. Network timeouts and
                5xx/408/429 responses are marked ``TRANSIENT`` (safe to retry); other
                failures stay ``PERMANENT``.
        """
        request = urllib.request.Request(
            self._url, data=body, method="POST", headers={"Content-Type": _CONTENT_TYPE}
        )
        logger.debug("POST %d bytes to %s", len(body), self._url)
        try:
            with urllib.request.urlopen(
                request, timeout=self._timeout, context=self._ssl_context
            ) as response:
                data: bytes = response.read()
                return data
        except urllib.error.HTTPError as error:
            transient = error.code in _TRANSIENT_STATUS or 500 <= error.code < 600
            raise _transport_error(
                f"EBICS endpoint returned HTTP {error.code}", transient=transient
            ) from error
        except (TimeoutError, urllib.error.URLError) as error:
            # Connection-level failures (timeout, reset, DNS) — transient for an
            # idempotent request; the caller decides whether to retry.
            raise _transport_error(
                f"Could not reach EBICS endpoint {self._url}: {error}", transient=True
            ) from error


def _build_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _transport_error(message: str, *, transient: bool) -> TransportError:
    error = TransportError(message)
    if transient:
        error.retryability = Retryability.TRANSIENT
    return error
