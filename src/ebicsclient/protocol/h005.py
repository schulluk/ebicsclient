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
from ebicsclient.certificates import (
    DEFAULT_CERTIFICATE_PROVIDER,
    BankCertificateVerifier,
    CertificateProvider,
)
from ebicsclient.errors import ProtocolError, ReturnCodeError
from ebicsclient.models import (
    Bank,
    BankKeys,
    BusinessTransactionFormat,
    DownloadInitialisation,
    DownloadSegment,
    Keyring,
    UploadPayload,
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
_ADMIN_ORDER_TYPE_BTU = "BTU"  # H005 business transaction upload
# The order carries an electronic signature (EU) and is authorised within EBICS. The H005 XSD
# types SignatureFlag as an empty flag, but banks expect the boolean text "true"; validated live.
_SIGNATURE_FLAG = "true"
# Cap each order-data segment at ~1 MB of base64 text, per the EBICS segmentation limit.
_MAX_SEGMENT_CHARS = 1_000_000
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


def build_ini_request(
    bank: Bank,
    user: User,
    keyring: Keyring,
    certificate_provider: CertificateProvider = DEFAULT_CERTIFICATE_PROVIDER,
) -> bytes:
    """Build the INI request submitting the signature public key (A006).

    Args:
        bank: The target bank.
        user: The subscriber.
        keyring: The subscriber's key pairs.
        certificate_provider: Supplies the signature certificate. Defaults to self-signed
            (the "mit Schlüsseln" profile); pass a CA-issued provider for "mit Zertifikaten".

    Returns:
        The serialised ``ebicsUnsecuredRequest`` XML.
    """
    certificate = certificate_provider.certificate(
        keys.CertificateUsage.SIGNATURE, keyring.signature, user.user_id
    )
    order_data = _signature_pubkey_order_data(user, certificate)
    return _unsecured_request(bank, user, "INI", order_data)


def build_hia_request(
    bank: Bank,
    user: User,
    keyring: Keyring,
    certificate_provider: CertificateProvider = DEFAULT_CERTIFICATE_PROVIDER,
) -> bytes:
    """Build the HIA request submitting the authentication (X002) and encryption (E002) keys.

    Args:
        bank: The target bank.
        user: The subscriber.
        keyring: The subscriber's key pairs.
        certificate_provider: Supplies the authentication and encryption certificates. Defaults
            to self-signed (the "mit Schlüsseln" profile); pass a CA-issued provider for
            "mit Zertifikaten".

    Returns:
        The serialised ``ebicsUnsecuredRequest`` XML.
    """
    authentication = certificate_provider.certificate(
        keys.CertificateUsage.AUTHENTICATION, keyring.authentication, user.user_id
    )
    encryption = certificate_provider.certificate(
        keys.CertificateUsage.ENCRYPTION, keyring.encryption, user.user_id
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
    response: bytes,
    keyring: Keyring,
    bank_certificate_verifier: BankCertificateVerifier | None = None,
) -> tuple[rsa.RSAPublicKey, rsa.RSAPublicKey]:
    """Decrypt an HPB response and extract the bank's public keys.

    Args:
        response: The raw ``ebicsKeyManagementResponse`` bytes from the bank.
        keyring: The subscriber's key pairs (the E002 key decrypts the response).
        bank_certificate_verifier: If given, validates each bank certificate before its key
            is trusted (the "mit Zertifikaten" profile). ``None`` extracts the keys without
            chain validation; the caller must still verify the published hashes out of band.

    Returns:
        The bank's authentication (X002) and encryption (E002) public keys, in that order.

    Raises:
        ProtocolError: the response could not be parsed or is missing required elements.
        ReturnCodeError: the bank reported a non-OK return code.
        BankCertificateError: a bank certificate failed verification.
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
        _public_key_from_info(
            bank_keys,
            "AuthenticationPubKeyInfo",
            keys.CertificateUsage.AUTHENTICATION,
            bank_certificate_verifier,
        ),
        _public_key_from_info(
            bank_keys,
            "EncryptionPubKeyInfo",
            keys.CertificateUsage.ENCRYPTION,
            bank_certificate_verifier,
        ),
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


def prepare_upload(
    user: User, keyring: Keyring, bank_keys: BankKeys, order_data: bytes
) -> UploadPayload:
    """Encrypt and sign order data once for an upload transaction.

    Generates a transaction key, signs the order data with the A006 key (the electronic
    signature), and encrypts both the signature and the order data with that key (the key
    itself wrapped to the bank's E002). The result feeds the initialisation and transfer
    requests, which must share this single encryption.

    Args:
        user: The subscriber (named in the signature data).
        keyring: The subscriber's key pairs (the A006 key signs the order data).
        bank_keys: The bank's public keys (the E002 key wraps the transaction key).
        order_data: The order data to upload (e.g. a pain.001 document).

    Returns:
        The prepared, encrypted upload payload.

    Raises:
        CryptoError: the order data could not be signed or encrypted.
    """
    transaction_key = crypto.new_transaction_key()
    signature = crypto.sign_order_data(keyring.signature, order_data)
    signature_xml = _user_signature_data(user, signature)
    signature_data = base64.b64encode(
        crypto.encrypt_with_transaction_key(transaction_key, signature_xml)
    ).decode("ascii")
    encrypted_stream = base64.b64encode(
        crypto.encrypt_with_transaction_key(transaction_key, order_data)
    ).decode("ascii")
    return UploadPayload(
        wrapped_transaction_key=crypto.encrypt_transaction_key(
            bank_keys.encryption, transaction_key
        ),
        data_digest=crypto.order_data_digest(order_data),
        signature_data=signature_data,
        order_data_segments=_split_segments(encrypted_stream),
    )


def _split_segments(stream: str) -> tuple[str, ...]:
    # The base64 stream is one unit; split it into <=1 MB pieces, at least one segment.
    if not stream:
        return ("",)
    return tuple(
        stream[index : index + _MAX_SEGMENT_CHARS]
        for index in range(0, len(stream), _MAX_SEGMENT_CHARS)
    )


def _user_signature_data(user: User, signature: bytes) -> bytes:
    root = etree.Element(etree.QName(S002_NAMESPACE, "UserSignatureData"), nsmap=_S002_NSMAP)
    order_signature = etree.SubElement(root, etree.QName(S002_NAMESPACE, "OrderSignatureData"))
    _s002_text(order_signature, "SignatureVersion", _SIGNATURE_VERSION)
    _s002_text(order_signature, "SignatureValue", base64.b64encode(signature).decode("ascii"))
    _s002_text(order_signature, "PartnerID", user.partner_id)
    _s002_text(order_signature, "UserID", user.user_id)
    return _serialize(root)


def build_upload_initialisation_request(
    bank: Bank,
    user: User,
    keyring: Keyring,
    bank_keys: BankKeys,
    btf: BusinessTransactionFormat,
    payload: UploadPayload,
) -> bytes:
    """Build the signed upload-initialisation request (BTU, phase Initialisation).

    Opens an upload transaction: the request carries the BTF, the segment count, the wrapped
    transaction key, the encrypted electronic signature, and the order-data digest, all under
    an ``AuthSignature`` signed with the X002 key. The bank replies with a transaction ID.

    Args:
        bank: The target bank.
        user: The subscriber.
        keyring: The subscriber's key pairs (the X002 key signs the request).
        bank_keys: The bank's public keys, digested into the request.
        btf: The Business Transaction Format to upload (e.g. ``PAIN_001``).
        payload: The prepared upload payload (from :func:`prepare_upload`).

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
    _text(order_details, "AdminOrderType", _ADMIN_ORDER_TYPE_BTU)
    _append_btu_order_params(order_details, btf)
    _append_bank_pub_key_digests(static, bank_keys)
    _text(static, "SecurityMedium", _SECURITY_MEDIUM)
    _text(static, "NumSegments", str(payload.num_segments))

    mutable = etree.SubElement(header, etree.QName(NAMESPACE, "mutable"))
    _text(mutable, "TransactionPhase", _PHASE_INITIALISATION)

    body = etree.SubElement(root, etree.QName(NAMESPACE, "body"))
    data_transfer = etree.SubElement(body, etree.QName(NAMESPACE, "DataTransfer"))
    encryption_info = etree.SubElement(data_transfer, etree.QName(NAMESPACE, "DataEncryptionInfo"))
    encryption_info.set("authenticate", "true")
    digest = _text(
        encryption_info,
        "EncryptionPubKeyDigest",
        base64.b64encode(keys.public_key_hash(bank_keys.encryption)).decode("ascii"),
    )
    digest.set("Version", _ENCRYPTION_VERSION)
    digest.set("Algorithm", _SHA256_ALGORITHM)
    _text(
        encryption_info,
        "TransactionKey",
        base64.b64encode(payload.wrapped_transaction_key).decode("ascii"),
    )
    signature_data = _text(data_transfer, "SignatureData", payload.signature_data)
    signature_data.set("authenticate", "true")
    data_digest = _text(
        data_transfer, "DataDigest", base64.b64encode(payload.data_digest).decode("ascii")
    )
    data_digest.set("SignatureVersion", _SIGNATURE_VERSION)

    # The header and the DataEncryptionInfo/SignatureData nodes are authenticated, so sign
    # after the body is built, then place the AuthSignature in schema order (header, sig, body).
    root.insert(1, crypto.build_auth_signature(root, keyring.authentication, NAMESPACE))
    return _serialize(root)


def _append_btu_order_params(order_details: etree._Element, btf: BusinessTransactionFormat) -> None:
    params = etree.SubElement(order_details, etree.QName(NAMESPACE, "BTUOrderParams"))
    service = etree.SubElement(params, etree.QName(NAMESPACE, "Service"))
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
    _text(params, "SignatureFlag", _SIGNATURE_FLAG)


def build_upload_transfer_request(
    bank: Bank,
    keyring: Keyring,
    transaction_id: str,
    segment_number: int,
    segment_data: str,
    *,
    last_segment: bool,
) -> bytes:
    """Build the signed request that uploads one order-data segment (phase Transfer).

    Args:
        bank: The target bank.
        keyring: The subscriber's key pairs (the X002 key signs the request).
        transaction_id: The transaction ID the bank issued during initialisation.
        segment_number: The 1-based number of the segment being sent.
        segment_data: The base64 order-data segment (from the prepared payload).
        last_segment: Whether this is the final segment of the upload.

    Returns:
        The serialised, signed ``ebicsRequest`` XML.
    """
    root, mutable = _transaction_request(bank, transaction_id)
    _text(mutable, "TransactionPhase", _PHASE_TRANSFER)
    segment = _text(mutable, "SegmentNumber", str(segment_number))
    segment.set("lastSegment", "true" if last_segment else "false")
    # Only the header is authenticated on a transfer, so sign it before appending the body.
    root.append(crypto.build_auth_signature(root, keyring.authentication, NAMESPACE))
    body = etree.SubElement(root, etree.QName(NAMESPACE, "body"))
    data_transfer = etree.SubElement(body, etree.QName(NAMESPACE, "DataTransfer"))
    _text(data_transfer, "OrderData", segment_data)
    return _serialize(root)


def parse_upload_initialisation_response(response: bytes) -> str:
    """Parse an upload-initialisation response and return the transaction ID.

    Args:
        response: The raw ``ebicsResponse`` bytes from the bank.

    Returns:
        The bank-issued transaction ID for the upload.

    Raises:
        ProtocolError: the response could not be parsed or is missing the transaction ID.
        ReturnCodeError: the bank rejected the initialisation (e.g. a bad signature).
    """
    root = _parse(response)
    _check_return_code(root)
    static = _child(_child(root, "header"), "static")
    return _child_text(static, "TransactionID")


def parse_upload_transfer_response(response: bytes) -> None:
    """Check an upload-transfer response's return code (raising on any non-OK code).

    Args:
        response: The raw ``ebicsResponse`` bytes from the bank.

    Raises:
        ProtocolError: the response could not be parsed or carries no return code.
        ReturnCodeError: the bank rejected the segment or the completed upload.
    """
    _check_return_code(_parse(response))


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


def _public_key_from_info(
    root: etree._Element,
    info_tag: str,
    usage: keys.CertificateUsage,
    verifier: BankCertificateVerifier | None,
) -> rsa.RSAPublicKey:
    info = root.find(f".//{{{NAMESPACE}}}{info_tag}")
    if info is None:
        raise ProtocolError(f"HPB response is missing <{info_tag}>")
    # H005 carries the bank key as an X.509 certificate; fall back to a plain RSAKeyValue
    # in case a bank sends the legacy representation.
    certificate = info.findtext(f".//{{{_DS}}}X509Certificate")
    if certificate is not None:
        return _public_key_from_certificate(certificate, info_tag, usage, verifier)
    if verifier is not None:
        # A verifier was required but the bank sent a bare key with no certificate to check.
        raise ProtocolError(
            f"HPB response <{info_tag}> carries no certificate to verify"
        )
    return _public_key_from_rsa_key_value(info, info_tag)


def _public_key_from_certificate(
    certificate_base64: str,
    info_tag: str,
    usage: keys.CertificateUsage,
    verifier: BankCertificateVerifier | None,
) -> rsa.RSAPublicKey:
    try:
        certificate = x509.load_der_x509_certificate(base64.b64decode(certificate_base64))
    except ValueError as error:
        raise ProtocolError(f"HPB response <{info_tag}> has an unreadable certificate") from error
    if verifier is not None:
        verifier.verify(certificate, usage)
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
