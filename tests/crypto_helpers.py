"""Test-only helpers that synthesise EBICS ciphertext and HPB responses.

The library is download-only, so it never *encrypts* order data; these helpers do, to
build fixtures that exercise the decryption and HPB-parsing paths without a live bank.
They deliberately mirror ``crypto.decrypt_order_data`` (AES-CBC, null IV, PKCS#7) so a
round trip proves the two are inverses.
"""

import base64
import os
import zlib

from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from lxml import etree

from ebicsclient.models import Keyring
from ebicsclient.protocol import h005

_NULL_IV = b"\x00" * 16
_DS = "http://www.w3.org/2000/09/xmldsig#"


def encrypt_order_data(
    public_key: rsa.RSAPublicKey, order_data: bytes, *, key_size: int = 16
) -> tuple[bytes, bytes]:
    """Compress, AES-encrypt order data, and RSA-encrypt the transaction key.

    Returns the (RSA-encrypted transaction key, AES-encrypted order data) pair, matching
    what an EBICS response carries.
    """
    symmetric_key = os.urandom(key_size)
    compressed = zlib.compress(order_data)
    padder = symmetric_padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(compressed) + padder.finalize()
    encryptor = Cipher(algorithms.AES(symmetric_key), modes.CBC(_NULL_IV)).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    transaction_key = public_key.encrypt(symmetric_key, padding.PKCS1v15())
    return transaction_key, encrypted


def make_hpb_response(
    subscriber_keyring: Keyring, bank_keyring: Keyring, *, host_id: str = "ZKBKCHZZ"
) -> bytes:
    """Build an OK HPB response carrying the bank's keys, encrypted to the subscriber."""
    order_data = _hpb_order_data(bank_keyring, host_id)
    transaction_key, encrypted = encrypt_order_data(
        subscriber_keyring.encryption.public_key(), order_data
    )
    namespace = h005.NAMESPACE
    root = etree.Element(
        etree.QName(namespace, "ebicsKeyManagementResponse"), nsmap={None: namespace}
    )
    root.set("Version", "H005")
    root.set("Revision", "1")
    header = etree.SubElement(root, etree.QName(namespace, "header"))
    mutable = etree.SubElement(header, etree.QName(namespace, "mutable"))
    etree.SubElement(mutable, etree.QName(namespace, "ReturnCode")).text = "000000"
    etree.SubElement(mutable, etree.QName(namespace, "ReportText")).text = "[EBICS_OK] OK"
    body = etree.SubElement(root, etree.QName(namespace, "body"))
    data_transfer = etree.SubElement(body, etree.QName(namespace, "DataTransfer"))
    encryption_info = etree.SubElement(data_transfer, etree.QName(namespace, "DataEncryptionInfo"))
    etree.SubElement(encryption_info, etree.QName(namespace, "TransactionKey")).text = (
        base64.b64encode(transaction_key).decode("ascii")
    )
    etree.SubElement(data_transfer, etree.QName(namespace, "OrderData")).text = base64.b64encode(
        encrypted
    ).decode("ascii")
    etree.SubElement(body, etree.QName(namespace, "ReturnCode")).text = "000000"
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def _hpb_order_data(bank_keyring: Keyring, host_id: str) -> bytes:
    namespace = h005.NAMESPACE
    root = etree.Element(
        etree.QName(namespace, "HPBResponseOrderData"), nsmap={None: namespace, "ds": _DS}
    )
    _pub_key_info(
        root, "AuthenticationPubKeyInfo", "AuthenticationVersion", "X002",
        bank_keyring.authentication.public_key(),
    )
    _pub_key_info(
        root, "EncryptionPubKeyInfo", "EncryptionVersion", "E002",
        bank_keyring.encryption.public_key(),
    )
    etree.SubElement(root, etree.QName(namespace, "HostID")).text = host_id
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def _pub_key_info(
    parent: etree._Element,
    info_tag: str,
    version_tag: str,
    version: str,
    public_key: rsa.RSAPublicKey,
) -> None:
    namespace = h005.NAMESPACE
    numbers = public_key.public_numbers()
    info = etree.SubElement(parent, etree.QName(namespace, info_tag))
    pub_key_value = etree.SubElement(info, etree.QName(namespace, "PubKeyValue"))
    rsa_key_value = etree.SubElement(pub_key_value, etree.QName(_DS, "RSAKeyValue"))
    etree.SubElement(rsa_key_value, etree.QName(_DS, "Modulus")).text = _b64_int(numbers.n)
    etree.SubElement(rsa_key_value, etree.QName(_DS, "Exponent")).text = _b64_int(numbers.e)
    etree.SubElement(info, etree.QName(namespace, version_tag)).text = version


def _b64_int(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.b64encode(value.to_bytes(length, "big")).decode("ascii")
