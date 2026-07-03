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

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from lxml import etree

from ebicsclient import crypto, keys
from ebicsclient.errors import ProtocolError, ReturnCodeError
from ebicsclient.models import Bank, Keyring, User

NAMESPACE = "urn:org:ebics:H005"
# EBICS signature keys (A006) are defined in their own S002 namespace, so the INI order
# data lives there — unlike the HIA order data, which is in the H005 namespace.
S002_NAMESPACE = "http://www.ebics.org/S002"
_DS = "http://www.w3.org/2000/09/xmldsig#"
_NSMAP = cast("dict[str, str]", {None: NAMESPACE, "ds": _DS})
_S002_NSMAP = cast("dict[str, str]", {None: S002_NAMESPACE, "ds": _DS})

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
    certificate = keys.generate_self_signed_certificate(
        keyring.signature, user.user_id, keys.CertificateUsage.SIGNATURE
    )
    order_data = _signature_pubkey_order_data(user, certificate)
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
    authentication = keys.generate_self_signed_certificate(
        keyring.authentication, user.user_id, keys.CertificateUsage.AUTHENTICATION
    )
    encryption = keys.generate_self_signed_certificate(
        keyring.encryption, user.user_id, keys.CertificateUsage.ENCRYPTION
    )
    order_data = _hia_request_order_data(user, authentication, encryption)
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
    # An EBICS response carries a *technical* ReturnCode in the header (well-formedness) and
    # the authoritative *order* ReturnCode in the body; both must be OK. Checking only the
    # first would miss a body-level rejection reported behind a header OK.
    return_codes = root.findall(f".//{{{NAMESPACE}}}ReturnCode")
    if not return_codes:
        raise ProtocolError("EBICS response carried no ReturnCode")
    for return_code in return_codes:
        if return_code.text is not None and return_code.text != _OK_RETURN_CODE:
            parent = return_code.getparent()
            report = parent.find(f"{{{NAMESPACE}}}ReportText") if parent is not None else None
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
    # H005 carries the bank key as an X.509 certificate; fall back to a plain RSAKeyValue
    # in case a bank sends the legacy representation.
    certificate = info.findtext(f".//{{{_DS}}}X509Certificate")
    if certificate is not None:
        return _public_key_from_certificate(certificate, info_tag)
    return _public_key_from_rsa_key_value(info, info_tag)


def _public_key_from_certificate(certificate_base64: str, info_tag: str) -> rsa.RSAPublicKey:
    try:
        certificate = x509.load_der_x509_certificate(base64.b64decode(certificate_base64))
    except ValueError as error:
        raise ProtocolError(f"HPB response <{info_tag}> has an unreadable certificate") from error
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ProtocolError(f"HPB response <{info_tag}> certificate does not hold an RSA key")
    return public_key


def _public_key_from_rsa_key_value(info: etree._Element, info_tag: str) -> rsa.RSAPublicKey:
    modulus = info.findtext(f".//{{{_DS}}}Modulus")
    exponent = info.findtext(f".//{{{_DS}}}Exponent")
    if modulus is None or exponent is None:
        raise ProtocolError(f"HPB response <{info_tag}> is missing a certificate or key value")
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


def _signature_pubkey_order_data(user: User, certificate: x509.Certificate) -> bytes:
    root = etree.Element(etree.QName(S002_NAMESPACE, "SignaturePubKeyOrderData"), nsmap=_S002_NSMAP)
    info = etree.SubElement(root, etree.QName(S002_NAMESPACE, "SignaturePubKeyInfo"))
    _append_x509_data(info, certificate)
    _s002_text(info, "SignatureVersion", _SIGNATURE_VERSION)
    _s002_text(root, "PartnerID", user.partner_id)
    _s002_text(root, "UserID", user.user_id)
    return _serialize(root)


def _hia_request_order_data(
    user: User, authentication: x509.Certificate, encryption: x509.Certificate
) -> bytes:
    root = etree.Element(etree.QName(NAMESPACE, "HIARequestOrderData"), nsmap=_NSMAP)
    auth_info = etree.SubElement(root, etree.QName(NAMESPACE, "AuthenticationPubKeyInfo"))
    _append_x509_data(auth_info, authentication)
    _text(auth_info, "AuthenticationVersion", _AUTHENTICATION_VERSION)
    enc_info = etree.SubElement(root, etree.QName(NAMESPACE, "EncryptionPubKeyInfo"))
    _append_x509_data(enc_info, encryption)
    _text(enc_info, "EncryptionVersion", _ENCRYPTION_VERSION)
    _text(root, "PartnerID", user.partner_id)
    _text(root, "UserID", user.user_id)
    return _serialize(root)


def _append_x509_data(pub_key_info: etree._Element, certificate: x509.Certificate) -> None:
    # EBICS H005 carries each public key as an X.509 certificate under ds:X509Data.
    x509_data = etree.SubElement(pub_key_info, etree.QName(_DS, "X509Data"))
    issuer_serial = etree.SubElement(x509_data, etree.QName(_DS, "X509IssuerSerial"))
    _ds_text(issuer_serial, "X509IssuerName", certificate.issuer.rfc4514_string())
    _ds_text(issuer_serial, "X509SerialNumber", str(certificate.serial_number))
    certificate_der = certificate.public_bytes(Encoding.DER)
    _ds_text(x509_data, "X509Certificate", base64.b64encode(certificate_der).decode("ascii"))


def _text(parent: etree._Element, local_name: str, text: str) -> etree._Element:
    element = etree.SubElement(parent, etree.QName(NAMESPACE, local_name))
    element.text = text
    return element


def _s002_text(parent: etree._Element, local_name: str, text: str) -> etree._Element:
    element = etree.SubElement(parent, etree.QName(S002_NAMESPACE, local_name))
    element.text = text
    return element


def _ds_text(parent: etree._Element, local_name: str, text: str) -> None:
    element = etree.SubElement(parent, etree.QName(_DS, local_name))
    element.text = text


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
