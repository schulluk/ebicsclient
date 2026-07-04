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
from ebicsclient.models import (
    Bank,
    BankKeys,
    BusinessTransactionFormat,
    DownloadInitialisation,
    DownloadSegment,
    Keyring,
    User,
)

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
_ADMIN_ORDER_TYPE_BTD = "BTD"  # H005 business transaction download
_SECURITY_MEDIUM = "0000"
_OK_RETURN_CODE = "000000"
_NONCE_BYTES = 16  # 128-bit nonce, rendered as uppercase hex
_SHA256_ALGORITHM = "http://www.w3.org/2001/04/xmlenc#sha256"
_PHASE_INITIALISATION = "Initialisation"
_PHASE_TRANSFER = "Transfer"
_PHASE_RECEIPT = "Receipt"
_RECEIPT_POSITIVE = "0"  # ReceiptCode acknowledging a successful download

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


def parse_download_initialisation_response(response: bytes) -> DownloadInitialisation:
    """Parse a download-initialisation response into its transaction handle and first segment.

    Args:
        response: The raw ``ebicsResponse`` bytes from the bank.

    Returns:
        The transaction ID, segment count, encrypted transaction key, and first order-data
        segment needed to fetch and decrypt the download.

    Raises:
        ProtocolError: the response could not be parsed or is missing required elements.
        ReturnCodeError: the bank reported a non-OK return code (e.g. no data available).
    """
    root = _parse(response)
    _check_return_code(root)
    static = _child(_child(root, "header"), "static")
    mutable = _child(_child(root, "header"), "mutable")
    data_transfer = _child(_child(root, "body"), "DataTransfer")
    encryption_info = _child(data_transfer, "DataEncryptionInfo")
    segment_number, last_segment = _segment(mutable)
    return DownloadInitialisation(
        transaction_id=_child_text(static, "TransactionID"),
        num_segments=_int(_child_text(static, "NumSegments"), "NumSegments"),
        transaction_key=base64.b64decode(_child_text(encryption_info, "TransactionKey")),
        segment_number=segment_number,
        last_segment=last_segment,
        order_data_segment=_child_text(data_transfer, "OrderData"),
    )


def parse_download_segment_response(response: bytes) -> DownloadSegment:
    """Parse a download-transfer response into one further order-data segment.

    Args:
        response: The raw ``ebicsResponse`` bytes from the bank.

    Returns:
        The segment number, whether it is the last segment, and its order-data segment.

    Raises:
        ProtocolError: the response could not be parsed or is missing required elements.
        ReturnCodeError: the bank reported a non-OK return code.
    """
    root = _parse(response)
    _check_return_code(root)
    mutable = _child(_child(root, "header"), "mutable")
    data_transfer = _child(_child(root, "body"), "DataTransfer")
    segment_number, last_segment = _segment(mutable)
    return DownloadSegment(
        segment_number=segment_number,
        last_segment=last_segment,
        order_data_segment=_child_text(data_transfer, "OrderData"),
    )


def build_download_initialisation_request(
    bank: Bank,
    user: User,
    keyring: Keyring,
    bank_keys: BankKeys,
    btf: BusinessTransactionFormat,
) -> bytes:
    """Build the signed download-initialisation request (BTD, phase Initialisation).

    Opens a download transaction for a Business Transaction Format: the request carries the
    BTF, the digests of the bank's expected keys, and an ``AuthSignature`` signed with the
    X002 key. The bank replies with a transaction ID, the segment count, and the first
    (encrypted) order-data segment.

    Args:
        bank: The target bank.
        user: The subscriber.
        keyring: The subscriber's key pairs (the X002 key signs the request).
        bank_keys: The bank's public keys (from HPB), digested into the request.
        btf: The Business Transaction Format to download (e.g. ``CAMT_053``).

    Returns:
        The serialised, signed ``ebicsRequest`` XML.
    """
    root = etree.Element(etree.QName(NAMESPACE, "ebicsRequest"), nsmap=_NSMAP)
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
    _text(order_details, "AdminOrderType", _ADMIN_ORDER_TYPE_BTD)
    _append_btd_order_params(order_details, btf)
    _append_bank_pub_key_digests(static, bank_keys)
    _text(static, "SecurityMedium", _SECURITY_MEDIUM)

    mutable = etree.SubElement(header, etree.QName(NAMESPACE, "mutable"))
    _text(mutable, "TransactionPhase", _PHASE_INITIALISATION)

    root.append(crypto.build_auth_signature(root, keyring.authentication, NAMESPACE))
    etree.SubElement(root, etree.QName(NAMESPACE, "body"))
    return _serialize(root)


def _append_btd_order_params(order_details: etree._Element, btf: BusinessTransactionFormat) -> None:
    params = etree.SubElement(order_details, etree.QName(NAMESPACE, "BTDOrderParams"))
    service = etree.SubElement(params, etree.QName(NAMESPACE, "Service"))
    # RestrictedServiceType order: ServiceName, Scope?, ServiceOption?, Container?, MsgName.
    _text(service, "ServiceName", btf.service_name)
    if btf.scope is not None:
        _text(service, "Scope", btf.scope)
    if btf.service_option is not None:
        _text(service, "ServiceOption", btf.service_option)
    if btf.container is not None:
        container = etree.SubElement(service, etree.QName(NAMESPACE, "Container"))
        container.set("containerType", btf.container)
    message = _text(service, "MsgName", btf.message_name)
    if btf.message_version is not None:
        message.set("version", btf.message_version)


def _append_bank_pub_key_digests(static: etree._Element, bank_keys: BankKeys) -> None:
    digests = etree.SubElement(static, etree.QName(NAMESPACE, "BankPubKeyDigests"))
    authentication = _text(
        digests,
        "Authentication",
        base64.b64encode(keys.public_key_hash(bank_keys.authentication)).decode("ascii"),
    )
    authentication.set("Version", _AUTHENTICATION_VERSION)
    authentication.set("Algorithm", _SHA256_ALGORITHM)
    encryption = _text(
        digests,
        "Encryption",
        base64.b64encode(keys.public_key_hash(bank_keys.encryption)).decode("ascii"),
    )
    encryption.set("Version", _ENCRYPTION_VERSION)
    encryption.set("Algorithm", _SHA256_ALGORITHM)


def build_download_transfer_request(
    bank: Bank, keyring: Keyring, transaction_id: str, segment_number: int, *, last_segment: bool
) -> bytes:
    """Build the signed request that fetches one further download segment (phase Transfer).

    Args:
        bank: The target bank.
        keyring: The subscriber's key pairs (the X002 key signs the request).
        transaction_id: The transaction ID the bank issued during initialisation.
        segment_number: The 1-based number of the segment being requested.
        last_segment: Whether this is the final segment of the transfer.

    Returns:
        The serialised, signed ``ebicsRequest`` XML.
    """
    root, mutable = _transaction_request(bank, transaction_id)
    _text(mutable, "TransactionPhase", _PHASE_TRANSFER)
    segment = _text(mutable, "SegmentNumber", str(segment_number))
    segment.set("lastSegment", "true" if last_segment else "false")
    root.append(crypto.build_auth_signature(root, keyring.authentication, NAMESPACE))
    etree.SubElement(root, etree.QName(NAMESPACE, "body"))
    return _serialize(root)


def build_download_receipt_request(bank: Bank, keyring: Keyring, transaction_id: str) -> bytes:
    """Build the signed request acknowledging a completed download (phase Receipt).

    Args:
        bank: The target bank.
        keyring: The subscriber's key pairs (the X002 key signs the request).
        transaction_id: The transaction ID the bank issued during initialisation.

    Returns:
        The serialised, signed ``ebicsRequest`` XML.
    """
    root, mutable = _transaction_request(bank, transaction_id)
    _text(mutable, "TransactionPhase", _PHASE_RECEIPT)
    body = etree.SubElement(root, etree.QName(NAMESPACE, "body"))
    receipt = etree.SubElement(body, etree.QName(NAMESPACE, "TransferReceipt"))
    receipt.set("authenticate", "true")
    _text(receipt, "ReceiptCode", _RECEIPT_POSITIVE)
    # The TransferReceipt is authenticated too, so sign after building it, then place the
    # AuthSignature in schema order (header, AuthSignature, body).
    root.insert(1, crypto.build_auth_signature(root, keyring.authentication, NAMESPACE))
    return _serialize(root)


def _transaction_request(bank: Bank, transaction_id: str) -> tuple[etree._Element, etree._Element]:
    root = etree.Element(etree.QName(NAMESPACE, "ebicsRequest"), nsmap=_NSMAP)
    root.set("Version", _PROTOCOL_VERSION)
    root.set("Revision", _REVISION)
    header = etree.SubElement(root, etree.QName(NAMESPACE, "header"))
    header.set("authenticate", "true")
    static = etree.SubElement(header, etree.QName(NAMESPACE, "static"))
    _text(static, "HostID", bank.host_id)
    _text(static, "TransactionID", transaction_id)
    mutable = etree.SubElement(header, etree.QName(NAMESPACE, "mutable"))
    return root, mutable


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


def _child(parent: etree._Element, local_name: str) -> etree._Element:
    # Direct-child lookup (not descendant), so nested elements sharing a name — the header
    # and body each carry a <ReturnCode>, for instance — are never confused.
    child = parent.find(f"{{{NAMESPACE}}}{local_name}")
    if child is None:
        raise ProtocolError(f"EBICS response is missing <{local_name}>")
    return child


def _child_text(parent: etree._Element, local_name: str) -> str:
    child = _child(parent, local_name)
    if child.text is None:
        raise ProtocolError(f"EBICS response has an empty <{local_name}>")
    return child.text


def _segment(mutable: etree._Element) -> tuple[int, bool]:
    segment = _child(mutable, "SegmentNumber")
    if segment.text is None:
        raise ProtocolError("EBICS response has an empty <SegmentNumber>")
    last_segment = segment.get("lastSegment")
    if last_segment is None:
        raise ProtocolError("EBICS response <SegmentNumber> is missing the lastSegment attribute")
    # XSD boolean: "true"/"false" or "1"/"0".
    return _int(segment.text, "SegmentNumber"), last_segment in ("true", "1")


def _int(text: str, local_name: str) -> int:
    try:
        return int(text)
    except ValueError as error:
        raise ProtocolError(f"EBICS response <{local_name}> is not an integer: {text!r}") from error


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
