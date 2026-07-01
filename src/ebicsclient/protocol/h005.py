"""H005 (EBICS 3.0) request envelopes and key-management response parsing.

Builds the ``ebicsUnsecuredRequest`` envelopes for key initialisation (INI submits the
A006 signature key; HIA submits the X002 authentication and E002 encryption keys) and
reads the return code from the bank's key-management response.

CAVEAT: the exact H005 envelope structure — element order, the key-management order
element, the order attribute, the security medium — is implemented from the EBICS 3.0
(H005) documentation and **must be validated against the H005 XSD and a bank test
platform**. The choices that encode that structure are gathered as named constants at
the top of this module so they are trivial to correct once verified.
"""

import base64
import datetime
import os
import zlib
from typing import cast

from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

from ebicsclient import crypto
from ebicsclient.errors import ProtocolError, ReturnCodeError
from ebicsclient.models import Bank, Keyring, User

NAMESPACE = "urn:org:ebics:H005"
_DS = "http://www.w3.org/2000/09/xmldsig#"
_NSMAP = cast("dict[str, str]", {None: NAMESPACE, "ds": _DS})

_PROTOCOL_VERSION = "H005"
_REVISION = "1"
_ADMIN_ORDER_TYPE_HPB = "HPB"  # H005 administrative order type for the bank-key download
_SECURITY_MEDIUM = "0000"
_OK_RETURN_CODE = "000000"
_NONCE_BYTES = 16  # 128-bit nonce, rendered as uppercase hex

# EBICS algorithm-version labels for the three keys.
_SIGNATURE_VERSION = "A006"
_AUTHENTICATION_VERSION = "X002"
_ENCRYPTION_VERSION = "E002"


def build_ini_request(bank: Bank, user: User, keyring: Keyring) -> bytes:
    """Build the INI request submitting the signature public key (A006).

    Args:
        bank: The target bank.
        user: The subscriber.
        keyring: The subscriber's key pairs.

    Returns:
        The serialised ``ebicsUnsecuredRequest`` XML.
    """
    order_data = _signature_pubkey_order_data(user, keyring.signature.public_key())
    return _unsecured_request(bank, user, "INI", order_data)


def build_hia_request(bank: Bank, user: User, keyring: Keyring) -> bytes:
    """Build the HIA request submitting the authentication (X002) and encryption (E002) keys.

    Args:
        bank: The target bank.
        user: The subscriber.
        keyring: The subscriber's key pairs.

    Returns:
        The serialised ``ebicsUnsecuredRequest`` XML.
    """
    order_data = _hia_request_order_data(
        user, keyring.authentication.public_key(), keyring.encryption.public_key()
    )
    return _unsecured_request(bank, user, "HIA", order_data)


def build_hpb_request(bank: Bank, user: User, keyring: Keyring) -> bytes:
    """Build the signed HPB request that downloads the bank's public keys.

    HPB is the first authenticated request: the subscriber does not yet hold the bank's
    keys, so it is sent as an ``ebicsNoPubKeyDigestsRequest`` carrying an ``AuthSignature``
    over the header (signed with the X002 authentication key) but no bank-key digests.

    Args:
        bank: The target bank.
        user: The subscriber.
        keyring: The subscriber's key pairs (the X002 key signs the request).

    Returns:
        The serialised, signed ``ebicsNoPubKeyDigestsRequest`` XML.
    """
    root = etree.Element(etree.QName(NAMESPACE, "ebicsNoPubKeyDigestsRequest"), nsmap=_NSMAP)
    root.set("Version", _PROTOCOL_VERSION)
    root.set("Revision", _REVISION)

    header = etree.SubElement(root, etree.QName(NAMESPACE, "header"))
    header.set("authenticate", "true")
    static = etree.SubElement(header, etree.QName(NAMESPACE, "static"))
    _text(static, "HostID", bank.host_id)
    _text(static, "Nonce", _nonce())
    _text(static, "Timestamp", _timestamp())
    _text(static, "PartnerID", user.partner_id)
    _text(static, "UserID", user.user_id)
    order_details = etree.SubElement(static, etree.QName(NAMESPACE, "OrderDetails"))
    _text(order_details, "AdminOrderType", _ADMIN_ORDER_TYPE_HPB)
    _text(static, "SecurityMedium", _SECURITY_MEDIUM)
    etree.SubElement(header, etree.QName(NAMESPACE, "mutable"))

    # Sign the authenticated nodes (the header), then place the AuthSignature and the
    # empty body in schema order: header, AuthSignature, body.
    root.append(crypto.build_auth_signature(root, keyring.authentication, NAMESPACE))
    etree.SubElement(root, etree.QName(NAMESPACE, "body"))
    return _serialize(root)


def parse_hpb_response(
    response: bytes, keyring: Keyring
) -> tuple[rsa.RSAPublicKey, rsa.RSAPublicKey]:
    """Decrypt an HPB response and extract the bank's public keys.

    Args:
        response: The raw ``ebicsKeyManagementResponse`` bytes from the bank.
        keyring: The subscriber's key pairs (the E002 key decrypts the response).

    Returns:
        The bank's authentication (X002) and encryption (E002) public keys, in that order.

    Raises:
        ProtocolError: the response could not be parsed or is missing required elements.
        ReturnCodeError: the bank reported a non-OK return code.
        CryptoError: the response order data could not be decrypted.
    """
    root = _parse(response)
    _check_return_code(root)
    transaction_key = base64.b64decode(_required_text(root, "TransactionKey"))
    encrypted_order_data = base64.b64decode(_required_text(root, "OrderData"))
    order_data = crypto.decrypt_order_data(
        keyring.encryption, transaction_key, encrypted_order_data
    )
    bank_keys = _parse(order_data)
    return (
        _public_key_from_info(bank_keys, "AuthenticationPubKeyInfo"),
        _public_key_from_info(bank_keys, "EncryptionPubKeyInfo"),
    )


def raise_for_return_code(response: bytes) -> None:
    """Raise if a key-management response carries a non-OK EBICS return code.

    Args:
        response: The raw response bytes from the bank.

    Raises:
        ProtocolError: the response could not be parsed or carries no return code.
        ReturnCodeError: the bank reported a non-OK return code (with its report text).
    """
    _check_return_code(_parse(response))


def _check_return_code(root: etree._Element) -> None:
    return_code = root.find(f".//{{{NAMESPACE}}}ReturnCode")
    if return_code is None or return_code.text is None:
        raise ProtocolError("EBICS response carried no ReturnCode")
    if return_code.text != _OK_RETURN_CODE:
        report = root.find(f".//{{{NAMESPACE}}}ReportText")
        raise ReturnCodeError(return_code.text, report.text if report is not None else None)


def _required_text(root: etree._Element, local_name: str) -> str:
    text = root.findtext(f".//{{{NAMESPACE}}}{local_name}")
    if text is None:
        raise ProtocolError(f"EBICS response is missing <{local_name}>")
    return text


def _public_key_from_info(root: etree._Element, info_tag: str) -> rsa.RSAPublicKey:
    info = root.find(f".//{{{NAMESPACE}}}{info_tag}")
    if info is None:
        raise ProtocolError(f"HPB response is missing <{info_tag}>")
    modulus = info.findtext(f".//{{{_DS}}}Modulus")
    exponent = info.findtext(f".//{{{_DS}}}Exponent")
    if modulus is None or exponent is None:
        raise ProtocolError(f"HPB response <{info_tag}> is missing a modulus or exponent")
    numbers = rsa.RSAPublicNumbers(
        int.from_bytes(base64.b64decode(exponent), "big"),
        int.from_bytes(base64.b64decode(modulus), "big"),
    )
    return numbers.public_key()


def _nonce() -> str:
    return os.urandom(_NONCE_BYTES).hex().upper()


def _timestamp() -> str:
    now = datetime.datetime.now(datetime.UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _unsecured_request(bank: Bank, user: User, order_type: str, order_data: bytes) -> bytes:
    root = etree.Element(etree.QName(NAMESPACE, "ebicsUnsecuredRequest"), nsmap=_NSMAP)
    root.set("Version", _PROTOCOL_VERSION)
    root.set("Revision", _REVISION)

    header = etree.SubElement(root, etree.QName(NAMESPACE, "header"))
    header.set("authenticate", "true")
    static = etree.SubElement(header, etree.QName(NAMESPACE, "static"))
    _text(static, "HostID", bank.host_id)
    _text(static, "PartnerID", user.partner_id)
    _text(static, "UserID", user.user_id)
    order_details = etree.SubElement(static, etree.QName(NAMESPACE, "OrderDetails"))
    _text(order_details, "AdminOrderType", order_type)
    _text(static, "SecurityMedium", _SECURITY_MEDIUM)
    etree.SubElement(header, etree.QName(NAMESPACE, "mutable"))

    body = etree.SubElement(root, etree.QName(NAMESPACE, "body"))
    data_transfer = etree.SubElement(body, etree.QName(NAMESPACE, "DataTransfer"))
    # Order data is deflate-compressed then base64-encoded inside <OrderData>.
    _text(data_transfer, "OrderData", base64.b64encode(zlib.compress(order_data)).decode("ascii"))
    return _serialize(root)


def _signature_pubkey_order_data(user: User, public_key: rsa.RSAPublicKey) -> bytes:
    root = etree.Element(etree.QName(NAMESPACE, "SignaturePubKeyOrderData"), nsmap=_NSMAP)
    info = etree.SubElement(root, etree.QName(NAMESPACE, "SignaturePubKeyInfo"))
    etree.SubElement(info, etree.QName(NAMESPACE, "PubKeyValue")).append(_rsa_key_value(public_key))
    _text(info, "SignatureVersion", _SIGNATURE_VERSION)
    _text(root, "PartnerID", user.partner_id)
    _text(root, "UserID", user.user_id)
    return _serialize(root)


def _hia_request_order_data(
    user: User, auth_key: rsa.RSAPublicKey, enc_key: rsa.RSAPublicKey
) -> bytes:
    root = etree.Element(etree.QName(NAMESPACE, "HIARequestOrderData"), nsmap=_NSMAP)
    auth_info = etree.SubElement(root, etree.QName(NAMESPACE, "AuthenticationPubKeyInfo"))
    etree.SubElement(auth_info, etree.QName(NAMESPACE, "PubKeyValue")).append(
        _rsa_key_value(auth_key)
    )
    _text(auth_info, "AuthenticationVersion", _AUTHENTICATION_VERSION)
    enc_info = etree.SubElement(root, etree.QName(NAMESPACE, "EncryptionPubKeyInfo"))
    etree.SubElement(enc_info, etree.QName(NAMESPACE, "PubKeyValue")).append(
        _rsa_key_value(enc_key)
    )
    _text(enc_info, "EncryptionVersion", _ENCRYPTION_VERSION)
    _text(root, "PartnerID", user.partner_id)
    _text(root, "UserID", user.user_id)
    return _serialize(root)


def _rsa_key_value(public_key: rsa.RSAPublicKey) -> etree._Element:
    numbers = public_key.public_numbers()
    rsa_key_value = etree.Element(etree.QName(_DS, "RSAKeyValue"))
    _ds_text(rsa_key_value, "Modulus", _int_to_base64(numbers.n))
    _ds_text(rsa_key_value, "Exponent", _int_to_base64(numbers.e))
    return rsa_key_value


def _text(parent: etree._Element, local_name: str, text: str) -> etree._Element:
    element = etree.SubElement(parent, etree.QName(NAMESPACE, local_name))
    element.text = text
    return element


def _ds_text(parent: etree._Element, local_name: str, text: str) -> None:
    element = etree.SubElement(parent, etree.QName(_DS, local_name))
    element.text = text


def _int_to_base64(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.b64encode(value.to_bytes(length, "big")).decode("ascii")


def _serialize(root: etree._Element) -> bytes:
    data: bytes = etree.tostring(root, xml_declaration=True, encoding="UTF-8")
    return data


def _parse(data: bytes) -> etree._Element:
    # Hardened parser: no entity expansion, no network, no huge trees (see docs/06).
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
    try:
        return etree.fromstring(data, parser=parser)
    except etree.XMLSyntaxError as error:
        raise ProtocolError(f"Malformed EBICS response: {error}") from error
