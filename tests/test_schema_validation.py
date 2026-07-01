"""Validate our requests against the authoritative EBICS H005 XSD schemas.

This is the external-oracle check for envelope and order-data *structure* — the thing
round-trip tests cannot give (a self-consistent but non-conformant request passes those).
It caught the AdminOrderType, S002-namespace, and X.509 requirements during development.

The schemas are not committed (see docs/08); run ``python tools/fetch-schemas.py`` to fetch
them, after which these tests run. CI should fetch them before pytest so they are not
silently skipped.
"""

import base64
import zlib
from pathlib import Path

import pytest
from lxml import etree

from ebicsclient import keys
from ebicsclient.models import Bank, Keyring, User
from ebicsclient.protocol import h005

_SCHEMA_DIR = Path(__file__).parent / "schema" / "H005"
_NS = h005.NAMESPACE

pytestmark = pytest.mark.skipif(
    not (_SCHEMA_DIR / "ebics_keymgmt_request_H005.xsd").is_file(),
    reason="H005 schemas absent — run `python tools/fetch-schemas.py` to enable schema validation",
)


@pytest.fixture(scope="module")
def keyring() -> Keyring:
    return keys.generate_keyring()


@pytest.fixture
def bank() -> Bank:
    return Bank(host_id="EBICSHOST", url="https://ebics.example.com/ebicsweb")


@pytest.fixture
def user() -> User:
    return User(partner_id="PARTNER1", user_id="USER1")


def _schema(name: str) -> etree.XMLSchema:
    return etree.XMLSchema(etree.parse(str(_SCHEMA_DIR / name)))


def _assert_valid(schema: etree.XMLSchema, document: etree._Element) -> None:
    if not schema.validate(document):
        messages = "\n".join(error.message for error in schema.error_log)
        pytest.fail(f"schema validation failed:\n{messages}")


def _order_data(request_bytes: bytes) -> etree._Element:
    encoded = etree.fromstring(request_bytes).findtext(f".//{{{_NS}}}OrderData")
    assert encoded is not None
    return etree.fromstring(zlib.decompress(base64.b64decode(encoded)))


@pytest.mark.parametrize("builder", ["build_ini_request", "build_hia_request", "build_hpb_request"])
def test_request_envelopes_validate(
    builder: str, bank: Bank, user: User, keyring: Keyring
) -> None:
    request = getattr(h005, builder)(bank, user, keyring)
    _assert_valid(_schema("ebics_keymgmt_request_H005.xsd"), etree.fromstring(request))


def test_ini_order_data_validates_against_the_s002_schema(
    bank: Bank, user: User, keyring: Keyring
) -> None:
    order_data = _order_data(h005.build_ini_request(bank, user, keyring))
    _assert_valid(_schema("ebics_signature_S002.xsd"), order_data)


def test_hia_order_data_validates_against_the_orders_schema(
    bank: Bank, user: User, keyring: Keyring
) -> None:
    order_data = _order_data(h005.build_hia_request(bank, user, keyring))
    _assert_valid(_schema("ebics_orders_H005.xsd"), order_data)
