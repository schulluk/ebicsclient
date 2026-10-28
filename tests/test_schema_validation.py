"""Validate our requests against the authoritative EBICS H005 XSD schemas.

This is the external-oracle check for envelope and order-data *structure* — the thing
round-trip tests cannot give (a self-consistent but non-conformant request passes those).
It caught the AdminOrderType, S002-namespace, and X.509 requirements during development.

The schemas are not committed (see docs/08); run ``python tools/fetch-schemas.py`` to fetch
them, after which these tests run. CI should fetch them before pytest so they are not
silently skipped.
"""

import base64
import datetime
import zlib
from pathlib import Path

import pytest
from lxml import etree

from ebicsclient import crypto, experimental, keys
from ebicsclient.models import (
    CAMT_053,
    PAIN_001,
    PAIN_001_CGI,
    Bank,
    BankKeys,
    BusinessTransactionFormat,
    DateRange,
    Keyring,
    KeyRotation,
    User,
)
from ebicsclient.protocol import h005, hev

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


def _bank_keys(bank_keyring: Keyring, *, with_certificates: bool = False) -> BankKeys:
    # With certificates the requests digest the certificates' DER (spec 5.5.1.1.1); without
    # them (a key carried over from EBICS 2.x) they digest the public key (spec 11.3.2.2).
    if not with_certificates:
        return BankKeys(
            authentication=bank_keyring.authentication.public_key(),
            encryption=bank_keyring.encryption.public_key(),
        )
    return BankKeys(
        authentication=bank_keyring.authentication.public_key(),
        encryption=bank_keyring.encryption.public_key(),
        authentication_certificate=keys.generate_self_signed_certificate(
            bank_keyring.authentication, "BANK", keys.CertificateUsage.AUTHENTICATION
        ),
        encryption_certificate=keys.generate_self_signed_certificate(
            bank_keyring.encryption, "BANK", keys.CertificateUsage.ENCRYPTION
        ),
    )


@pytest.mark.parametrize("with_certificates", [False, True])
def test_download_initialisation_request_validates(
    with_certificates: bool, bank: Bank, user: User, keyring: Keyring
) -> None:
    # Both digest forms must fit PubKeyDigestType (DigestType = base64Binary, plus the
    # Algorithm and Version attributes): the certificate hash and the public-key hash.
    request = h005.build_download_initialisation_request(
        bank,
        user,
        keyring,
        _bank_keys(keys.generate_keyring(), with_certificates=with_certificates),
        CAMT_053,
    )
    _assert_valid(_schema("ebics_request_H005.xsd"), etree.fromstring(request))


def test_dated_download_initialisation_request_validates(
    bank: Bank, user: User, keyring: Keyring
) -> None:
    # The XSD is the oracle for DateRange: it must sit after <Service> and before any
    # Parameter in BTDOrderParams (BTDParamsType), with inclusive Start/End dates.
    request = h005.build_download_initialisation_request(
        bank,
        user,
        keyring,
        _bank_keys(keys.generate_keyring()),
        CAMT_053,
        DateRange(datetime.date(2026, 6, 1), datetime.date(2026, 6, 30)),
    )
    _assert_valid(_schema("ebics_request_H005.xsd"), etree.fromstring(request))


def test_download_transfer_request_validates(bank: Bank, keyring: Keyring) -> None:
    request = h005.build_download_transfer_request(
        bank, keyring, "A" * 32, 2, last_segment=True
    )
    _assert_valid(_schema("ebics_request_H005.xsd"), etree.fromstring(request))


@pytest.mark.parametrize(("positive", "expected_code"), [(True, "0"), (False, "1")])
def test_download_receipt_request_validates(
    positive: bool, expected_code: str, bank: Bank, keyring: Keyring
) -> None:
    # Both acknowledgement polarities must be schema-valid: 0 (positive, consume) and 1
    # (negative, keep). ReceiptCodeType restricts to 0..1 (ebics_types_H005.xsd).
    request = h005.build_download_receipt_request(bank, keyring, "A" * 32, positive=positive)
    document = etree.fromstring(request)
    _assert_valid(_schema("ebics_request_H005.xsd"), document)
    assert document.findtext(f".//{{{_NS}}}ReceiptCode") == expected_code


@pytest.mark.parametrize("admin_order_type", ["HAA", "HTD", "HKD", "HPD", "HAC"])
def test_admin_download_request_validates(
    admin_order_type: str, bank: Bank, user: User, keyring: Keyring
) -> None:
    request = h005.build_admin_download_initialisation_request(
        bank, user, keyring, _bank_keys(keys.generate_keyring()), admin_order_type
    )
    _assert_valid(_schema("ebics_request_H005.xsd"), etree.fromstring(request))


@pytest.mark.parametrize("with_certificates", [False, True])
@pytest.mark.parametrize("btf", [PAIN_001, PAIN_001_CGI, experimental.PAIN_001_SEPA])
def test_upload_initialisation_request_validates(
    btf: BusinessTransactionFormat,
    with_certificates: bool,
    bank: Bank,
    user: User,
    keyring: Keyring,
) -> None:
    # PAIN_001_CGI adds a ServiceOption and PAIN_001_SEPA drops the Scope: both shapes must hold,
    # with the bank keys named by certificate hash and by public-key hash alike. SignatureFlag
    # is the empty element the schema defines (FlagAttribType), so the whole request validates;
    # until 2026-10-28 it carried the text "true", the one deviation this test had to allow.
    bank_keys = _bank_keys(keys.generate_keyring(), with_certificates=with_certificates)
    payload = h005.prepare_upload(user, keyring, bank_keys, b"<Document>pay</Document>")
    request = h005.build_upload_initialisation_request(
        bank, user, keyring, bank_keys, btf, payload
    )
    _assert_valid(_schema("ebics_request_H005.xsd"), etree.fromstring(request))


def test_upload_transfer_request_validates(bank: Bank, keyring: Keyring) -> None:
    request = h005.build_upload_transfer_request(
        bank, keyring, "A" * 32, 1, "c2VnbWVudA==", last_segment=True
    )
    _assert_valid(_schema("ebics_request_H005.xsd"), etree.fromstring(request))


@pytest.mark.parametrize(
    ("rotation", "schema_name"),
    [
        # Spec 4.6.1.2: PUB order data is the INI structure (S002); HCA and HCS have their
        # own H005 order-data elements.
        (KeyRotation.SIGNATURE, "ebics_signature_S002.xsd"),
        (KeyRotation.AUTHENTICATION_AND_ENCRYPTION, "ebics_orders_H005.xsd"),
        (KeyRotation.ALL, "ebics_orders_H005.xsd"),
    ],
)
def test_key_change_order_data_validates(
    rotation: KeyRotation, schema_name: str, user: User, keyring: Keyring
) -> None:
    successor = keys.rotate_keyring(keyring, rotation)
    order_data = etree.fromstring(h005.build_key_change_order_data(user, successor, rotation))
    _assert_valid(_schema(schema_name), order_data)


@pytest.mark.parametrize("rotation", list(KeyRotation))
def test_key_change_initialisation_request_validates(
    rotation: KeyRotation, bank: Bank, user: User, keyring: Keyring
) -> None:
    # The admin upload carries no SignatureFlag; it validates like the BTU upload above.
    bank_keys = _bank_keys(keys.generate_keyring())
    successor = keys.rotate_keyring(keyring, rotation)
    payload = h005.prepare_upload(
        user, keyring, bank_keys, h005.build_key_change_order_data(user, successor, rotation)
    )
    request = h005.build_key_change_initialisation_request(
        bank, user, keyring, bank_keys, rotation, payload
    )
    _assert_valid(_schema("ebics_request_H005.xsd"), etree.fromstring(request))


def test_suspension_request_validates(bank: Bank, user: User, keyring: Keyring) -> None:
    # SPR has no order data: NumSegments 0, which NumSegmentsType (a nonNegativeInteger)
    # admits, and an ES file the bank decrypts to an S002 UserSignatureData.
    bank_keyring = keys.generate_keyring()
    request = h005.build_suspension_request(bank, user, keyring, _bank_keys(bank_keyring))
    document = etree.fromstring(request)
    _assert_valid(_schema("ebics_request_H005.xsd"), document)
    transaction_key = document.findtext(f".//{{{_NS}}}TransactionKey")
    signature_data = document.findtext(f".//{{{_NS}}}SignatureData")
    assert transaction_key is not None and signature_data is not None
    signature_file = crypto.decrypt_order_data(
        bank_keyring.encryption, base64.b64decode(transaction_key), base64.b64decode(signature_data)
    )
    _assert_valid(_schema("ebics_signature_S002.xsd"), etree.fromstring(signature_file))


@pytest.mark.parametrize(
    "fixture", ["spr_response_zkb_sample.xml", "spr_suspended_response_zkb_sample.xml"]
)
def test_suspension_response_fixtures_validate(fixture: str) -> None:
    # ZKB's real answers to SPR: the parser tests rely on their shape.
    document = etree.parse(str(Path(__file__).parent / "data" / fixture))
    _assert_valid(_schema("ebics_response_H005.xsd"), document.getroot())


@pytest.mark.parametrize(
    "fixture", ["hpd_zkb_sample.xml", "hkd_zkb_sample.xml", "hkd_accounts_example.xml"]
)
def test_admin_order_data_fixtures_validate(fixture: str) -> None:
    # The parser tests trust these fixtures, so the XSD vouches for them first — the
    # hand-written account example especially, which has no live counterpart.
    document = etree.parse(str(Path(__file__).parent / "data" / fixture))
    _assert_valid(_schema("ebics_orders_H005.xsd"), document.getroot())


_HEV_SCHEMA = Path(__file__).parent / "schema" / "H000" / "ebics_hev.xsd"
_HEV_SCHEMA_ABSENT = pytest.mark.skipif(
    not _HEV_SCHEMA.is_file(),
    reason="HEV schema absent — run `python tools/fetch-schemas.py` to enable schema validation",
)


@_HEV_SCHEMA_ABSENT
def test_hev_request_validates(bank: Bank) -> None:
    schema = etree.XMLSchema(etree.parse(str(_HEV_SCHEMA)))
    _assert_valid(schema, etree.fromstring(hev.build_request(bank)))


@_HEV_SCHEMA_ABSENT
def test_hev_response_fixture_validates() -> None:
    schema = etree.XMLSchema(etree.parse(str(_HEV_SCHEMA)))
    document = etree.parse(str(Path(__file__).parent / "data" / "hev_zkb_sample.xml"))
    _assert_valid(schema, document.getroot())
