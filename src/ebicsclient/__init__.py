"""ebicsclient — a pure-Python client for the EBICS 3.0 (H005) banking protocol.

The public API is curated here and stays protocol- and format-agnostic; see
docs/04-implementation-plan.md for the module layout and docs/06-engineering-conventions.md
for the conventions every addition must follow.
"""

import logging
from importlib.metadata import PackageNotFoundError, version

from ebicsclient.errors import (
    CryptoError,
    EbicsError,
    KeyringError,
    ProtocolError,
    ReturnCodeError,
    TransportError,
)
from ebicsclient.keys import generate_keyring, load_keyring, public_key_hash, save_keyring
from ebicsclient.models import Keyring

# A library must never configure logging — that is the application's job. Attach a
# NullHandler so importing the package never emits "No handlers could be found"
# warnings when the consuming application has not set logging up. See docs/06.
logging.getLogger(__name__).addHandler(logging.NullHandler())

try:
    __version__ = version("ebicsclient")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0"

__all__ = [
    "CryptoError",
    "EbicsError",
    "Keyring",
    "KeyringError",
    "ProtocolError",
    "ReturnCodeError",
    "TransportError",
    "__version__",
    "generate_keyring",
    "load_keyring",
    "public_key_hash",
    "save_keyring",
]
