"""Cryptographic mechanics for EBICS requests.

Provides inclusive XML canonicalisation, SHA-256 digests, RSA-SHA256 signatures, and
the ``AuthSignature`` that every ``ebicsRequest`` carries over the nodes flagged
``authenticate="true"``.

The authentication signature is the protocol's most failure-prone area — its security
rests on *byte-exact* canonicalisation. EBICS mandates **inclusive Canonical XML 1.0**
(``http://www.w3.org/TR/2001/REC-xml-c14n-20010315``) for both the CanonicalizationMethod
and the Reference transform — confirmed against the EBICS Common Implementation Guide and
the H005 XSD. This is *not* exclusive c14n.

**Caveat:** a self round-trip proves internal consistency, not agreement with the bank.
The digest construction has been cross-checked against the H005 schema and an independent
canonicaliser, but must still be validated against a bank test platform (see docs/01, 08).
"""

import base64
import copy
import hashlib
import zlib
from typing import cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from lxml import etree

from ebicsclient.errors import CryptoError

# XML-DSig algorithm identifiers used by EBICS.
_DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
_INCLUSIVE_C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"

# Every node the bank authenticates is flagged authenticate="true"; the AuthSignature
# digest is taken over exactly those nodes, in document order.
_AUTHENTICATE_NODES = etree.XPath("//*[@authenticate='true']")
_REFERENCE_URI = "#xpointer(//*[@authenticate='true'])"

# EBICS encrypts order data with AES in CBC mode under a null initialisation vector; the
# AES (transaction) key is itself RSA-encrypted to the recipient's E002 key. The null IV
# and the padding scheme are part of the protocol's failure-prone area #2 and must be
# validated against a bank test platform (see docs/01).
_NULL_IV = b"\x00" * 16


def canonicalize(element: etree._Element) -> bytes:
    """Serialise an element with inclusive Canonical XML 1.0 (the EBICS c14n).

    EBICS signs over inclusive Canonical XML 1.0, which renders every in-scope namespace
    (including inherited ones) on the apex of the canonicalised subtree.

    lxml's ``method="c14n"`` mis-handles a subtree whose default namespace is declared on
    an *ancestor* outside the subtree: it emits a spurious ``xmlns=""`` on same-namespace
    descendants, producing bytes no spec-compliant canonicaliser agrees with. To avoid
    that, the element is rebuilt as its own document root with all in-scope namespaces
    (``element.nsmap`` already resolves inherited declarations) materialised on it; libxml
    then canonicalises it correctly. Verified byte-for-byte against the H005 XSD context
    and an independent canonicaliser (see docs/08).

    Args:
        element: The element subtree to canonicalise.

    Returns:
        The inclusively-canonicalised XML as bytes.
    """
    # element.nsmap resolves inherited declarations, but its None default-namespace key
    # trips lxml-stubs (which model nsmap keys as str); cast to satisfy the type checker.
    nsmap = cast("dict[str, str]", element.nsmap)
    standalone = etree.Element(element.tag, nsmap=nsmap)
    for name, value in element.attrib.items():
        standalone.set(name, value)
    standalone.text = element.text
    standalone.extend(copy.deepcopy(child) for child in element)
    canonical: bytes = etree.tostring(standalone, method="c14n", with_comments=False)
    return canonical


def sha256_digest(data: bytes) -> bytes:
    """Return the SHA-256 digest of ``data``."""
    return hashlib.sha256(data).digest()


def sign_rsa_sha256(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """Sign ``data`` with RSASSA-PKCS1-v1.5 over SHA-256 (the EBICS X002 scheme).

    Args:
        private_key: The signing private key (the X002 authentication key).
        data: The bytes to sign.

    Returns:
        The raw signature bytes.
    """
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def verify_rsa_sha256(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """Verify an RSA-SHA256 signature over ``data``.

    Args:
        public_key: The public key to verify against.
        data: The signed bytes.
        signature: The signature to check.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def decrypt_order_data(
    encryption_key: rsa.RSAPrivateKey, transaction_key: bytes, encrypted_order_data: bytes
) -> bytes:
    """Decrypt and inflate EBICS order data.

    Reverses EBICS order-data protection: the RSA-encrypted transaction key is recovered
    with the E002 private key, used as an AES key (CBC mode, null IV) to decrypt the order
    data, then the plaintext is PKCS#7-unpadded and DEFLATE-inflated.

    Args:
        encryption_key: The subscriber's E002 encryption private key.
        transaction_key: The RSA-encrypted symmetric transaction key (raw bytes).
        encrypted_order_data: The AES-encrypted, deflate-compressed order data (raw bytes).

    Returns:
        The decompressed order-data XML bytes.

    Raises:
        CryptoError: the transaction key or the order data could not be decrypted or inflated.
    """
    try:
        symmetric_key = encryption_key.decrypt(transaction_key, padding.PKCS1v15())
    except ValueError as error:
        raise CryptoError("Could not decrypt the EBICS transaction key") from error
    try:
        decryptor = Cipher(algorithms.AES(symmetric_key), modes.CBC(_NULL_IV)).decryptor()
        padded = decryptor.update(encrypted_order_data) + decryptor.finalize()
        unpadder = symmetric_padding.PKCS7(algorithms.AES.block_size).unpadder()
        compressed = unpadder.update(padded) + unpadder.finalize()
        return zlib.decompress(compressed)
    except (ValueError, zlib.error) as error:
        raise CryptoError("Could not decrypt the EBICS order data") from error


def digest_authenticated_nodes(root: etree._Element) -> bytes:
    """Compute the SHA-256 digest that the AuthSignature signs over.

    Every element marked ``authenticate="true"`` is inclusively canonicalised, in
    document order; the canonical forms are concatenated and the SHA-256 of that
    concatenation is returned.

    Args:
        root: The request root to scan for authenticated nodes.

    Returns:
        The 32-byte SHA-256 digest.

    Raises:
        CryptoError: the request contains no ``authenticate="true"`` nodes.
    """
    result = _AUTHENTICATE_NODES(root)
    if not isinstance(result, list) or not result:
        raise CryptoError('Request has no authenticate="true" nodes to sign')
    nodes = cast("list[etree._Element]", result)
    concatenated = b"".join(canonicalize(node) for node in nodes)
    return sha256_digest(concatenated)


def build_auth_signature(
    root: etree._Element, private_key: rsa.RSAPrivateKey, ebics_namespace: str
) -> etree._Element:
    """Build the ``AuthSignature`` element for a request.

    Computes the digest over the request's authenticated nodes, assembles the
    ``ds:SignedInfo`` (exclusive c14n + RSA-SHA256, referencing those nodes), signs the
    canonicalised SignedInfo with the X002 authentication key, and returns the populated
    ``AuthSignature`` element. The caller inserts it into the request in schema order
    (after the header, before the body).

    Args:
        root: The request root, with its header/body already flagged authenticate="true".
        private_key: The X002 authentication private key.
        ebics_namespace: The EBICS schema namespace for the AuthSignature element
            (e.g. ``"urn:org:ebics:H005"``).

    Returns:
        The ``AuthSignature`` element, ready to insert into the request.
    """
    digest_value = digest_authenticated_nodes(root)
    # A None key sets the default namespace — valid at runtime, but the lxml type stubs
    # model nsmap keys as str only, so cast to satisfy the type checker.
    nsmap = cast("dict[str, str]", {None: ebics_namespace, "ds": _DS_NAMESPACE})
    auth_signature = etree.Element(etree.QName(ebics_namespace, "AuthSignature"), nsmap=nsmap)
    signed_info = _build_signed_info(auth_signature, digest_value)
    signature = sign_rsa_sha256(private_key, canonicalize(signed_info))
    signature_value = etree.SubElement(auth_signature, etree.QName(_DS_NAMESPACE, "SignatureValue"))
    signature_value.text = base64.b64encode(signature).decode("ascii")
    return auth_signature


def verify_auth_signature(root: etree._Element, public_key: rsa.RSAPublicKey) -> bool:
    """Verify the ``AuthSignature`` on a request against the X002 public key.

    Recomputes the digest over the authenticated nodes, checks it matches the value in
    the signature's Reference, and verifies the SignatureValue over the canonicalised
    SignedInfo.

    Args:
        root: The request root, including its AuthSignature.
        public_key: The X002 authentication public key.

    Returns:
        True if the signature is present and valid, False otherwise.
    """
    signed_info = root.find(f".//{{{_DS_NAMESPACE}}}SignedInfo")
    signature_value = root.find(f".//{{{_DS_NAMESPACE}}}SignatureValue")
    if signed_info is None or signature_value is None or signature_value.text is None:
        return False
    digest_value = signed_info.find(f".//{{{_DS_NAMESPACE}}}DigestValue")
    if digest_value is None or digest_value.text is None:
        return False

    # The referenced digest must match the current authenticated nodes.
    if base64.b64decode(digest_value.text) != digest_authenticated_nodes(root):
        return False

    signature = base64.b64decode(signature_value.text)
    return verify_rsa_sha256(public_key, canonicalize(signed_info), signature)


def _build_signed_info(parent: etree._Element, digest_value: bytes) -> etree._Element:
    signed_info = etree.SubElement(parent, etree.QName(_DS_NAMESPACE, "SignedInfo"))
    etree.SubElement(
        signed_info, etree.QName(_DS_NAMESPACE, "CanonicalizationMethod"), Algorithm=_INCLUSIVE_C14N
    )
    etree.SubElement(
        signed_info, etree.QName(_DS_NAMESPACE, "SignatureMethod"), Algorithm=_RSA_SHA256
    )
    reference = etree.SubElement(
        signed_info, etree.QName(_DS_NAMESPACE, "Reference"), URI=_REFERENCE_URI
    )
    transforms = etree.SubElement(reference, etree.QName(_DS_NAMESPACE, "Transforms"))
    etree.SubElement(transforms, etree.QName(_DS_NAMESPACE, "Transform"), Algorithm=_INCLUSIVE_C14N)
    etree.SubElement(reference, etree.QName(_DS_NAMESPACE, "DigestMethod"), Algorithm=_SHA256)
    digest_element = etree.SubElement(reference, etree.QName(_DS_NAMESPACE, "DigestValue"))
    digest_element.text = base64.b64encode(digest_value).decode("ascii")
    return signed_info
