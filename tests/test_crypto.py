"""Tests for ebicsclient.crypto: canonicalisation, digests, and the AuthSignature.

These prove the signature mechanics are internally consistent (sign → verify, tamper
detection). They do *not* prove agreement with a real bank — the exact digest
construction must still be validated against a bank test platform.
"""

import pytest
from lxml import etree

from crypto_helpers import encrypt_order_data
from ebicsclient import crypto, keys
from ebicsclient.errors import CryptoError
from ebicsclient.models import Keyring

_EBICS_NS = "urn:org:ebics:H005"


@pytest.fixture(scope="module")
def keyring() -> Keyring:
    return keys.generate_keyring()


def _make_request() -> etree._Element:
    root = etree.Element(etree.QName(_EBICS_NS, "ebicsRequest"), nsmap={None: _EBICS_NS})
    header = etree.SubElement(root, etree.QName(_EBICS_NS, "header"))
    header.set("authenticate", "true")
    etree.SubElement(header, etree.QName(_EBICS_NS, "StaticHeader")).text = "static-data"
    body = etree.SubElement(root, etree.QName(_EBICS_NS, "body"))
    body.set("authenticate", "true")
    etree.SubElement(body, etree.QName(_EBICS_NS, "DataTransfer")).text = "payload"
    return root


def test_sign_and_verify_round_trip(keyring: Keyring) -> None:
    data = b"the quick brown fox"
    signature = crypto.sign_rsa_sha256(keyring.authentication, data)
    public_key = keyring.authentication.public_key()
    assert crypto.verify_rsa_sha256(public_key, data, signature)
    assert not crypto.verify_rsa_sha256(public_key, b"tampered", signature)


def test_exclusive_c14n_drops_inherited_unused_namespaces() -> None:
    # The defining property of exclusive c14n: an inherited but unused namespace
    # declaration is not emitted on the canonicalised child.
    doc = etree.fromstring(b'<a xmlns:unused="urn:x"><child>text</child></a>')
    canonical = crypto.canonicalize_exclusive(doc[0])
    assert b"unused" not in canonical
    assert canonical == b"<child>text</child>"


def test_digest_authenticated_nodes_is_deterministic() -> None:
    root = _make_request()
    digest = crypto.digest_authenticated_nodes(root)
    assert len(digest) == 32
    assert digest == crypto.digest_authenticated_nodes(root)


def test_digest_changes_when_an_authenticated_node_changes() -> None:
    root = _make_request()
    before = crypto.digest_authenticated_nodes(root)
    root.find(f".//{{{_EBICS_NS}}}StaticHeader").text = "changed"
    assert crypto.digest_authenticated_nodes(root) != before


def test_digest_requires_authenticated_nodes() -> None:
    root = etree.Element(etree.QName(_EBICS_NS, "ebicsRequest"), nsmap={None: _EBICS_NS})
    with pytest.raises(CryptoError):
        crypto.digest_authenticated_nodes(root)


def test_auth_signature_round_trips(keyring: Keyring) -> None:
    root = _make_request()
    auth_signature = crypto.build_auth_signature(root, keyring.authentication, _EBICS_NS)
    root.insert(1, auth_signature)  # header, AuthSignature, body
    assert crypto.verify_auth_signature(root, keyring.authentication.public_key())


def test_auth_signature_detects_tampering_after_signing(keyring: Keyring) -> None:
    root = _make_request()
    root.insert(1, crypto.build_auth_signature(root, keyring.authentication, _EBICS_NS))
    root.find(f".//{{{_EBICS_NS}}}StaticHeader").text = "tampered"
    assert not crypto.verify_auth_signature(root, keyring.authentication.public_key())


def test_auth_signature_rejects_a_wrong_key(keyring: Keyring) -> None:
    root = _make_request()
    root.insert(1, crypto.build_auth_signature(root, keyring.authentication, _EBICS_NS))
    other_keyring = keys.generate_keyring()
    assert not crypto.verify_auth_signature(root, other_keyring.authentication.public_key())


def test_verify_returns_false_when_signature_is_absent(keyring: Keyring) -> None:
    root = _make_request()  # never signed
    assert not crypto.verify_auth_signature(root, keyring.authentication.public_key())


def test_decrypt_order_data_round_trips(keyring: Keyring) -> None:
    plaintext = b"<OrderData>closing balance</OrderData>" * 40
    transaction_key, encrypted = encrypt_order_data(keyring.encryption.public_key(), plaintext)
    recovered = crypto.decrypt_order_data(keyring.encryption, transaction_key, encrypted)
    assert recovered == plaintext


def test_decrypt_order_data_rejects_an_unrecoverable_transaction_key(keyring: Keyring) -> None:
    with pytest.raises(CryptoError):
        crypto.decrypt_order_data(keyring.encryption, b"not a valid RSA ciphertext", b"")
