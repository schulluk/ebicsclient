"""High-level EBICS client orchestration.

Ties the keyring, protocol envelopes, and transport together into the operations a
caller performs: the key-initialisation handshake (INI, HIA) and — once activated —
fetching the bank's keys (HPB) and downloading statements.
"""

import base64
import logging
from collections.abc import Callable, Sequence
from typing import TypeVar

from ebicsclient import crypto, keys, letter
from ebicsclient.certificates import (
    DEFAULT_CERTIFICATE_PROVIDER,
    BankCertificateVerifier,
    CertificateProvider,
)
from ebicsclient.errors import (
    BankKeyMismatchError,
    ClientStateError,
    DateRangeMismatchError,
    EbicsError,
    KeyChangeUnconfirmedError,
    MessageFormatError,
    MessageVersionMismatchError,
    ReturnCodeError,
    UnknownReturnCodeError,
)
from ebicsclient.formats import camt052, camt053, camt054, iso20022, pain002
from ebicsclient.formats.container import extract_documents
from ebicsclient.models import (
    CAMT_052,
    CAMT_053,
    CAMT_054,
    PAIN_002,
    Bank,
    BankKeyHashes,
    BankKeys,
    BankParameters,
    BusinessTransactionFormat,
    CustomerInfo,
    DateRange,
    Entry,
    InitializationState,
    Keyring,
    KeyRotation,
    Letter,
    Notification,
    OutputFormat,
    PaymentStatusReport,
    ReceiptPolicy,
    Statement,
    SubscriberInfo,
    UploadPayload,
    User,
    VersionPolicy,
)
from ebicsclient.protocol import h005
from ebicsclient.transport import Transport

logger = logging.getLogger(__name__)

# EBICS_INVALID_USER_OR_USER_STATE — on a key-submission re-run this means the subscriber
# is already initialised; it is also how the bank reports an unknown subscriber (which then
# surfaces at HPB), so we identify it but do not treat a re-run as a hard failure.
_SUBSCRIBER_STATE_INADMISSIBLE = "091002"

# The version check reads only each delivered document's root start tag, so it inflates
# no more of a ZIP entry than this. The XML declaration, any leading comments and the root
# tag of a real delivery take a few hundred bytes; a document whose root tag does not fit
# cannot be identified and counts as unreadable.
_DOCUMENT_HEAD_LENGTH = 64 * 1024


_Parsed = TypeVar("_Parsed")


def _entries_in_range_check(
    date_range: DateRange,
) -> Callable[[Sequence[Statement | Notification]], None]:
    """Build a check asserting every parsed booking entry falls within ``date_range``.

    ``DateRange`` is an optional EBICS element a bank may accept without honouring; if it
    ignores the filter and serves other data, the booking dates give it away. Booking dates
    (not value dates, which can be forward-dated; not balance dates, whose opening balance
    legitimately predates the range) are the reliable signal that the returned data belongs
    to the requested period. An entry without a booking date, or a period with no entries,
    is not evidence of a mismatch and passes.
    """

    def check(documents: Sequence[Statement | Notification]) -> None:
        for document in documents:
            for entry in document.entries:
                _assert_entry_in_range(entry, date_range)

    return check


def _assert_entry_in_range(entry: Entry, date_range: DateRange) -> None:
    booking = entry.booking_date
    if booking is not None and not (date_range.start <= booking <= date_range.end):
        raise DateRangeMismatchError(
            f"The bank returned an entry booked {booking.isoformat()}, outside the requested "
            f"range {date_range.start.isoformat()}..{date_range.end.isoformat()} — the bank "
            f"may not support DateRange filtering. The data was NOT acknowledged and remains "
            f"available at the bank."
        )


def _version_mismatch(btf: BusinessTransactionFormat, order_data: bytes) -> str | None:
    """Describe the first delivered document that is not the message and version ``btf`` names.

    The comparison reads each document's root namespace, which for ISO 20022 names the
    exact message, variant and version (see :mod:`ebicsclient.formats.iso20022`). The
    request carries no variant, so only the message name and version are compared. A
    document that names no ISO 20022 message cannot be shown to match and counts as a
    mismatch.

    Returns:
        What the first mismatching document declares (e.g. ``"camt.053.001.04"``), or
        ``None`` if every document is the requested message and version.

    Raises:
        MessageFormatError: the data is not a readable container or XML document.
    """
    for document in extract_documents(order_data, prefix_length=_DOCUMENT_HEAD_LENGTH):
        namespace = iso20022.root_namespace(document)
        delivered = iso20022.message_identifier(namespace)
        if delivered is None:
            if namespace is None:
                return "a document that declares no namespace"
            return f"a document in namespace {namespace!r}, which names no ISO 20022 message"
        if (delivered.message_name, delivered.version) != (btf.message_name, btf.message_version):
            return str(delivered)
    return None


def _version_policy_check(
    btf: BusinessTransactionFormat, version_policy: VersionPolicy
) -> Callable[[bytes], None]:
    """Build the pre-receipt check that applies ``version_policy`` to a download of ``btf``.

    ``STRICT`` raises on a mismatch, so the download is not acknowledged. ``ACCEPT_ANY``
    logs a warning and lets the download continue; it never raises, so the lenient policy
    cannot fail a download it would otherwise have returned.
    """
    requested = f"{btf.message_name} version {btf.message_version}"

    def strict_check(order_data: bytes) -> None:
        delivered = _version_mismatch(btf, order_data)
        if delivered is not None:
            raise MessageVersionMismatchError(requested=requested, delivered=delivered)

    def lenient_check(order_data: bytes) -> None:
        try:
            delivered = _version_mismatch(btf, order_data)
        except MessageFormatError:
            # The error text is not logged: it describes the order data, which never
            # goes to the log (docs/06). A typed download raises it from its parser.
            logger.warning(
                "Download: requested %s, but the delivered data is not readable XML, so "
                "its version could not be compared",
                requested,
            )
            return
        if delivered is not None:
            logger.warning(
                "Download: requested %s, the bank delivered %s. Returned anyway under "
                "VersionPolicy.ACCEPT_ANY; VersionPolicy.STRICT would reject it and leave "
                "the data at the bank",
                requested,
                delivered,
            )

    return strict_check if version_policy is VersionPolicy.STRICT else lenient_check


class Client:
    """An EBICS client for one subscriber at one bank."""

    def __init__(
        self,
        bank: Bank,
        user: User,
        keyring: Keyring,
        *,
        transport: Transport | None = None,
        certificate_provider: CertificateProvider = DEFAULT_CERTIFICATE_PROVIDER,
        bank_certificate_verifier: BankCertificateVerifier | None = None,
        version_policy: VersionPolicy = VersionPolicy.ACCEPT_ANY,
    ) -> None:
        """Configure the client.

        Args:
            bank: The target bank.
            user: The subscriber's identifiers.
            keyring: The subscriber's key pairs.
            transport: Transport to use; defaults to an HTTPS transport for ``bank.url``.
            certificate_provider: Supplies the subscriber's certificates for INI/HIA. Defaults
                to self-signed certificates (the "mit Schlüsseln" profile); pass a
                :class:`~ebicsclient.certificates.MappingCertificateProvider` (or your own) with
                CA-issued certificates for the "mit Zertifikaten" profile.
            bank_certificate_verifier: If given, validates the bank's certificates during HPB
                (e.g. :class:`~ebicsclient.certificates.TrustAnchorVerifier`). ``None`` skips
                chain validation; you must still verify the published bank-key hashes.
            version_policy: Whether every download must deliver the message version its
                BTF requested (see :class:`~ebicsclient.VersionPolicy`). ``ACCEPT_ANY``
                (default) returns whatever the bank delivered and logs a warning on a
                mismatch; ``STRICT`` rejects a mismatch before the receipt, leaving the
                data at the bank.

        Raises:
            TypeError: ``version_policy`` is not a :class:`~ebicsclient.VersionPolicy`.
        """
        if not isinstance(version_policy, VersionPolicy):
            # A plain "strict" string would compare unequal to VersionPolicy.STRICT by
            # identity and silently run the lenient policy instead.
            raise TypeError(
                f"version_policy must be a VersionPolicy, got {type(version_policy).__name__}"
            )
        self._bank = bank
        self._user = user
        self._keyring = keyring
        self._transport = transport if transport is not None else Transport(bank.url)
        self._certificate_provider = certificate_provider
        self._bank_certificate_verifier = bank_certificate_verifier
        self._version_policy = version_policy
        self._bank_keys: BankKeys | None = None

    @property
    def bank_keys(self) -> BankKeys | None:
        """The bank's public keys once HPB has run, or ``None`` before then."""
        return self._bank_keys

    @property
    def keyring(self) -> Keyring:
        """The subscriber's current key pairs (the successor's after a :meth:`change_keys`)."""
        return self._keyring

    def make_ini_letter(
        self,
        *,
        output_format: OutputFormat = OutputFormat.AUTO,
        branding: str = "ebicsClient",
    ) -> Letter:
        """Render the initialisation letters (INI and HIA) to print, sign, and send.

        The letters carry the subscriber's certificates and their SHA-256 DER
        fingerprints (EBICS 3.0 spec, section 4.4.1.2.3) so the bank can verify, out of
        band, the certificates it received electronically over INI and HIA. They are
        rendered from this client's certificate provider, so the printed fingerprints
        match the certificates :meth:`ini` and :meth:`hia` transmitted.

        Args:
            output_format: The output format. ``AUTO`` renders PDF when the optional
                ``pdf`` extra is installed, otherwise HTML.
            branding: A name shown in the letters' footer; defaults to ``"ebicsClient"``.

        Returns:
            The rendered letters (format, media type, and content bytes) — the INI
            letter and the HIA letter, each on its own page.

        Raises:
            MissingDependencyError: PDF output was requested without the ``pdf`` extra.
        """
        return letter.make_ini_letter(
            self._bank,
            self._user,
            self._keyring,
            certificate_provider=self._certificate_provider,
            output_format=output_format,
            branding=branding,
        )

    def ini(self) -> InitializationState:
        """Send INI — submit the signature public key (A006) to the bank.

        Idempotent: if the subscriber is already initialised the bank rejects the re-run
        (return code ``091002``), which is reported as ``ALREADY_INITIALISED`` rather than
        raised.

        .. warning::
            ``ALREADY_INITIALISED`` means the bank did **not** receive this run's
            certificate — it kept whatever an earlier INI delivered. If the keyring or
            the certificates changed since then (a key rotation, a client upgrade), the
            initialisation letter will not match what the bank holds and activation will
            fail: have the bank delete/reset the subscriber's initialisation first, then
            re-run INI and HIA and confirm both return ``SUBMITTED`` before printing the
            letters.

        Returns:
            Whether the key was newly submitted or the subscriber was already initialised.

        Raises:
            TransportError: the request could not be delivered.
            ProtocolError: the response could not be parsed.
            ReturnCodeError: the bank rejected the submission for another reason.
        """
        logger.info("INI: submitting the signature key for user %s", self._user.user_id)
        request = h005.build_ini_request(
            self._bank, self._user, self._keyring, self._certificate_provider
        )
        return self._submit_keys(request, "INI")

    def hia(self) -> InitializationState:
        """Send HIA — submit the authentication (X002) and encryption (E002) public keys.

        Idempotent in the same way as :meth:`ini` — and with the same warning:
        ``ALREADY_INITIALISED`` means the bank kept its previously received certificates,
        so a changed keyring requires a bank-side reset before the re-run.

        Returns:
            Whether the keys were newly submitted or the subscriber was already initialised.

        Raises:
            TransportError: the request could not be delivered.
            ProtocolError: the response could not be parsed.
            ReturnCodeError: the bank rejected the submission for another reason.
        """
        logger.info(
            "HIA: submitting the authentication and encryption keys for user %s", self._user.user_id
        )
        request = h005.build_hia_request(
            self._bank, self._user, self._keyring, self._certificate_provider
        )
        return self._submit_keys(request, "HIA")

    def _submit_keys(self, request: bytes, order: str) -> InitializationState:
        try:
            h005.raise_for_return_code(self._transport.post(request))
        except ReturnCodeError as error:
            if error.code == _SUBSCRIBER_STATE_INADMISSIBLE:
                # Benign ONLY when re-sending the same keys. The bank's response is
                # identical when the keyring changed since the first submission — in that
                # case the new certificates were silently NOT delivered and the letters
                # will not match (observed live: bank error 17104 on activation). The
                # response carries no way to distinguish the two, so warn loudly.
                logger.warning(
                    "%s: subscriber %s already initialised — the bank KEPT its previously "
                    "received certificates and this run's were NOT delivered (%s). If the "
                    "keyring or certificates changed since the first submission, have the "
                    "bank reset the initialisation and re-run until this returns SUBMITTED.",
                    order,
                    self._user.user_id,
                    error.text,
                )
                return InitializationState.ALREADY_INITIALISED
            raise
        return InitializationState.SUBMITTED

    def hpb(self, *, pinned: BankKeyHashes | None = None) -> BankKeys:
        """Send HPB — download, store, and return the bank's public keys.

        Sends a signed HPB request, decrypts the response with the E002 key, and stores
        the bank's authentication (X002) and encryption (E002) public keys on the client
        (also available via :attr:`bank_keys`). Verify their hashes against the values the
        bank publishes out of band before trusting them.

        Args:
            pinned: If given, the downloaded keys must hash to these values or
                :class:`~ebicsclient.errors.BankKeyMismatchError` is raised. Pin to a
                previously trusted set (:func:`~ebicsclient.bank_key_hashes` after a first
                HPB, persisted by you) or to the bank's published hashes. ``None`` disables
                pinning.

        Returns:
            The bank's public keys.

        Raises:
            TransportError: the request could not be delivered.
            ProtocolError: the response could not be parsed.
            ReturnCodeError: the bank rejected the request.
            BankKeyMismatchError: pinning was requested and the keys did not match.
            CryptoError: the response could not be decrypted.
        """
        logger.info("HPB: requesting the bank's public keys from host %s", self._bank.host_id)
        request = h005.build_hpb_request(self._bank, self._user, self._keyring)
        authentication, encryption = h005.parse_hpb_response(
            self._transport.post(request), self._keyring, self._bank_certificate_verifier
        )
        bank_keys = BankKeys(authentication=authentication, encryption=encryption)
        if pinned is not None:
            self._verify_pinned(bank_keys, pinned)
        self._bank_keys = bank_keys
        return self._bank_keys

    @staticmethod
    def _verify_pinned(bank_keys: BankKeys, pinned: BankKeyHashes) -> None:
        actual = keys.bank_key_hashes(bank_keys)
        if actual != pinned:
            # The keys are not what we pinned — do not store or trust them.
            raise BankKeyMismatchError(
                "The bank's HPB keys do not match the pinned hashes; refusing to trust them"
            )

    def download(
        self,
        btf: BusinessTransactionFormat,
        *,
        date_range: DateRange | None = None,
        receipt_policy: ReceiptPolicy = ReceiptPolicy.ACKNOWLEDGE,
        validate: Callable[[bytes], None] | None = None,
    ) -> bytes:
        """Download order data for a Business Transaction Format and return the plaintext.

        Runs the full download transaction: it opens the transaction (initialisation),
        fetches every further segment (transfer), decrypts and inflates the order data, and
        only then acknowledges it. Acknowledging last is deliberate — the receipt is what
        lets the bank consume the data, so a failure to decrypt or validate sends a negative
        receipt and the bank keeps the data rather than losing it. The bank's keys must
        already be available (call :meth:`hpb` first).

        Args:
            btf: The Business Transaction Format to download (e.g. ``CAMT_053``).
            date_range: An optional inclusive reporting period. When given, the bank returns
                the messages for that period (the EBICS ``DateRange`` order parameter) rather
                than the default not-yet-delivered data. Whether a bank re-serves data it has
                already delivered for a past range is bank-specific — confirm before relying
                on a dated re-download.
            receipt_policy: What to do with the data once received (see
                :class:`~ebicsclient.ReceiptPolicy`). ``ACKNOWLEDGE`` (default) consumes it;
                ``KEEP`` leaves it available for a later download (a non-consuming read).
            validate: An optional check run on the decrypted order data *before* the receipt.
                If it raises, the download is not acknowledged (negative receipt) and the
                exception propagates — the seam the typed convenience methods use to parse
                and check the data before it is consumed. The client's
                :class:`~ebicsclient.VersionPolicy` check runs first.

        Returns:
            The decrypted, decompressed order-data bytes. For a container format this is the
            container itself — e.g. ``CAMT_053`` yields a ZIP of camt.053 documents.

        Raises:
            ClientStateError: the bank's keys have not been fetched yet (run HPB first).
            TransportError: a request could not be delivered.
            ProtocolError: a response could not be parsed.
            ReturnCodeError: the bank reported a non-OK return code (e.g. no data available).
            CryptoError: the order data could not be decrypted.
            MessageVersionMismatchError: under ``VersionPolicy.STRICT``, a delivered document
                is not the message and version ``btf`` requested (the download is left
                un-acknowledged).
            MessageFormatError: under ``VersionPolicy.STRICT``, a delivered document is not
                readable XML (the download is left un-acknowledged).
        """
        validate = self._with_version_policy(btf, validate)
        bank_keys = self._require_bank_keys("Download")
        logger.info(
            "Download: opening a %s/%s transaction%s",
            btf.service_name,
            btf.message_name,
            f" for {date_range.start.isoformat()}..{date_range.end.isoformat()}"
            if date_range is not None
            else "",
        )
        request = h005.build_download_initialisation_request(
            self._bank, self._user, self._keyring, bank_keys, btf, date_range
        )
        return self._run_download_transaction(
            request, bank_keys, validate=validate, receipt_policy=receipt_policy
        )

    def _with_version_policy(
        self,
        btf: BusinessTransactionFormat,
        validate: Callable[[bytes], None] | None,
    ) -> Callable[[bytes], None] | None:
        # A BTF without a message_version requests no version, so there is nothing to
        # compare; every other download checks the delivery before the caller's check.
        if btf.message_version is None:
            return validate
        version_check = _version_policy_check(btf, self._version_policy)
        if validate is None:
            return version_check
        caller_check = validate

        def check_version_then_validate(order_data: bytes) -> None:
            version_check(order_data)
            caller_check(order_data)

        return check_version_then_validate

    def _download_parsed(
        self,
        btf: BusinessTransactionFormat,
        parse: Callable[[bytes], list[_Parsed]],
        *,
        date_range: DateRange | None,
        receipt_policy: ReceiptPolicy,
        check: Callable[[list[_Parsed]], None] | None = None,
    ) -> list[_Parsed]:
        # Parse (and check) inside the pre-receipt hook rather than on the returned bytes:
        # data the library cannot parse, or that fails a check, must stay at the bank
        # (negative receipt) instead of being consumed by a positive receipt sent first.
        parsed: list[_Parsed] = []

        def parse_before_receipt(order_data: bytes) -> None:
            documents = parse(order_data)
            if check is not None:
                check(documents)
            parsed.extend(documents)

        self.download(
            btf,
            date_range=date_range,
            receipt_policy=receipt_policy,
            validate=parse_before_receipt,
        )
        return parsed

    def _require_bank_keys(self, operation: str) -> BankKeys:
        if self._bank_keys is None:
            raise ClientStateError(f"{operation} requires the bank's keys; call hpb() first")
        return self._bank_keys

    def _post_verified(self, request: bytes, bank_keys: BankKeys) -> bytes:
        # Every ebicsResponse is authenticated with the bank's X002 signature; verify it
        # BEFORE trusting anything in the response — including its return code.
        response = self._transport.post(request)
        h005.verify_response_signature(response, bank_keys.authentication)
        return response

    def _run_download_transaction(
        self,
        initialisation_request: bytes,
        bank_keys: BankKeys,
        *,
        validate: Callable[[bytes], None] | None = None,
        receipt_policy: ReceiptPolicy = ReceiptPolicy.ACKNOWLEDGE,
    ) -> bytes:
        initialisation = h005.parse_download_initialisation_response(
            self._post_verified(initialisation_request, bank_keys)
        )

        # Order data is one base64 stream split into NumSegments pieces: fetch the rest, in
        # order, driven by the authoritative segment count from the initialisation response.
        segments = [initialisation.order_data_segment]
        for number in range(2, initialisation.num_segments + 1):
            transfer = h005.build_download_transfer_request(
                self._bank,
                self._keyring,
                initialisation.transaction_id,
                number,
                last_segment=number == initialisation.num_segments,
            )
            segment = h005.parse_download_segment_response(
                self._post_verified(transfer, bank_keys)
            )
            segments.append(segment.order_data_segment)

        transaction_id = initialisation.transaction_id
        # Decrypt and validate BEFORE acknowledging: the receipt is what lets the bank
        # consume the data, so nothing is acknowledged until we have safely landed it. Any
        # failure here sends a NEGATIVE receipt, so the bank keeps the data for redelivery
        # rather than losing it to a positive ack we could not honour.
        try:
            # The segments are pieces of a single base64 stream, so join before decoding — a
            # segment boundary need not fall on a 4-character base64 group.
            encrypted_order_data = base64.b64decode("".join(segments))
            order_data = crypto.decrypt_order_data(
                self._keyring.encryption, initialisation.transaction_key, encrypted_order_data
            )
            if validate is not None:
                validate(order_data)
        except Exception:
            self._acknowledge(transaction_id, bank_keys, positive=False)
            raise

        # Success. ACKNOWLEDGE consumes the data (positive receipt); KEEP declines it
        # (negative receipt) so the bank keeps it available for a later download.
        positive = receipt_policy is ReceiptPolicy.ACKNOWLEDGE
        self._acknowledge(transaction_id, bank_keys, positive=positive)
        logger.info(
            "Download: received %d segment(s) for transaction %s (%s)",
            initialisation.num_segments,
            transaction_id,
            "acknowledged" if positive else "kept — negative receipt",
        )
        return order_data

    def _acknowledge(
        self, transaction_id: str, bank_keys: BankKeys, *, positive: bool
    ) -> None:
        receipt = h005.build_download_receipt_request(
            self._bank, self._keyring, transaction_id, positive=positive
        )
        try:
            h005.parse_download_receipt_response(self._post_verified(receipt, bank_keys))
        except Exception:
            if positive:
                # A failed positive acknowledgement is a real error: the caller must know
                # the consume did not complete cleanly.
                raise
            # A negative acknowledgement is best-effort — it is sent either to preserve data
            # after a failure (whose exception must not be masked) or for a KEEP read. Log
            # and carry on; the data stays un-consumed either way.
            logger.warning(
                "Negative acknowledgement for transaction %s could not be confirmed; "
                "the bank should still not have marked the data delivered",
                transaction_id,
            )

    def available_order_types(self) -> list[BusinessTransactionFormat]:
        """Download the order types for which the bank currently holds data (HAA).

        Runs the administrative ``HAA`` download and returns the Business Transaction
        Formats with data waiting — an authoritative "is there anything to fetch?" check.
        The bank's keys must already be available (call :meth:`hpb` first).

        Returns:
            The order types with data available (empty when nothing is waiting).

        Raises:
            ClientStateError: the bank's keys have not been fetched yet (run HPB first).
            TransportError: a request could not be delivered.
            ProtocolError: a response could not be parsed.
            ResponseAuthenticationError: a response failed signature verification.
            ReturnCodeError: the bank rejected the request.
            CryptoError: the order data could not be decrypted.
        """
        bank_keys = self._require_bank_keys("HAA")
        logger.info("HAA: requesting the order types with data available")
        request = h005.build_admin_download_initialisation_request(
            self._bank, self._user, self._keyring, bank_keys, "HAA"
        )
        return h005.parse_available_order_types(
            self._run_download_transaction(request, bank_keys)
        )

    def subscriber_info(self) -> SubscriberInfo:
        """Download the bank's registered data for this subscriber (HTD).

        Runs the administrative ``HTD`` download and returns the bank's authoritative
        view of the subscriber: the user's status and name, the permissions granted, and
        every order type registered for the partner — the ground truth for diagnosing
        rejected order types. The bank's keys must already be available (call :meth:`hpb`
        first).

        Returns:
            The subscriber's registered data.

        Raises:
            ClientStateError: the bank's keys have not been fetched yet (run HPB first).
            TransportError: a request could not be delivered.
            ProtocolError: a response could not be parsed.
            ResponseAuthenticationError: a response failed signature verification.
            ReturnCodeError: the bank rejected the request.
            CryptoError: the order data could not be decrypted.
        """
        bank_keys = self._require_bank_keys("HTD")
        logger.info("HTD: requesting the subscriber data registered at the bank")
        request = h005.build_admin_download_initialisation_request(
            self._bank, self._user, self._keyring, bank_keys, "HTD"
        )
        return h005.parse_subscriber_info(self._run_download_transaction(request, bank_keys))

    def customer_info(self) -> CustomerInfo:
        """Download the bank's registered data for the customer and all its subscribers (HKD).

        Runs the administrative ``HKD`` download. Where :meth:`subscriber_info` (HTD) shows
        only this subscriber, HKD is the customer-wide view: the address, the accounts, the
        order types registered for the customer, and every subscriber with their
        permissions and signature classes. The bank's keys must already be available (call
        :meth:`hpb` first).

        Returns:
            The customer's registered data.

        Raises:
            ClientStateError: the bank's keys have not been fetched yet (run HPB first).
            TransportError: a request could not be delivered.
            ProtocolError: a response could not be parsed.
            ResponseAuthenticationError: a response failed signature verification.
            ReturnCodeError: the bank rejected the request.
            CryptoError: the order data could not be decrypted.
        """
        bank_keys = self._require_bank_keys("HKD")
        logger.info("HKD: requesting the customer and subscriber data registered at the bank")
        request = h005.build_admin_download_initialisation_request(
            self._bank, self._user, self._keyring, bank_keys, "HKD"
        )
        return h005.parse_customer_info(self._run_download_transaction(request, bank_keys))

    def bank_parameters(self) -> BankParameters:
        """Download the bank's EBICS access and protocol parameters (HPD).

        Runs the administrative ``HPD`` download and returns the bank's published
        addresses, the EBICS protocol and key versions it accepts, and which optional
        features (recovery, pre-validation, HKD/HTD, HAA) it supports. The bank's keys must
        already be available (call :meth:`hpb` first).

        Returns:
            The bank's parameters.

        Raises:
            ClientStateError: the bank's keys have not been fetched yet (run HPB first).
            TransportError: a request could not be delivered.
            ProtocolError: a response could not be parsed.
            ResponseAuthenticationError: a response failed signature verification.
            ReturnCodeError: the bank rejected the request.
            CryptoError: the order data could not be decrypted.
        """
        bank_keys = self._require_bank_keys("HPD")
        logger.info("HPD: requesting the bank parameters")
        request = h005.build_admin_download_initialisation_request(
            self._bank, self._user, self._keyring, bank_keys, "HPD"
        )
        return h005.parse_bank_parameters(self._run_download_transaction(request, bank_keys))

    def download_statements(
        self,
        *,
        date_range: DateRange | None = None,
        receipt_policy: ReceiptPolicy = ReceiptPolicy.ACKNOWLEDGE,
    ) -> list[Statement]:
        """Download the end-of-period camt.053 statements and parse them.

        A convenience over :meth:`download` for the common case: it fetches
        ``EOP/camt.053`` and returns the parsed statements (account, balances, entries).
        The bank's keys must already be available (call :meth:`hpb` first).

        Args:
            date_range: An optional inclusive reporting period (see :meth:`download`); when
                given, fetches the statements for that period instead of the default
                not-yet-delivered data, and every returned entry's booking date is asserted
                to fall within it (:class:`~ebicsclient.errors.DateRangeMismatchError`
                otherwise — the download is left un-acknowledged).
            receipt_policy: What to do with the data once received (see
                :class:`~ebicsclient.ReceiptPolicy`); ``KEEP`` reads without consuming.

        Returns:
            The account statements the bank delivered, in document order.

        Raises:
            ClientStateError: the bank's keys have not been fetched yet (run HPB first).
            TransportError: a request could not be delivered.
            ProtocolError: a response could not be parsed.
            ReturnCodeError: the bank reported a non-OK return code (e.g. no data available).
            CryptoError: the order data could not be decrypted.
            DateRangeMismatchError: a returned entry falls outside ``date_range``.
            MessageFormatError: the downloaded camt.053 data could not be parsed (the
                download is left un-acknowledged).
            MessageVersionMismatchError: under ``VersionPolicy.STRICT``, the bank
                delivered another message version (the download is left
                un-acknowledged).
        """
        return self._download_parsed(
            CAMT_053,
            camt053.parse,
            date_range=date_range,
            receipt_policy=receipt_policy,
            check=_entries_in_range_check(date_range) if date_range else None,
        )

    def download_intraday_statements(
        self,
        *,
        date_range: DateRange | None = None,
        receipt_policy: ReceiptPolicy = ReceiptPolicy.ACKNOWLEDGE,
    ) -> list[Statement]:
        """Download the intraday camt.052 account reports and parse them.

        A convenience over :meth:`download` for ``STM/camt.052``. Intraday reports share
        the statement shape; interim balances (if any) are in ``balances`` rather than
        ``opening_balance``/``closing_balance``. The bank's keys must already be available
        (call :meth:`hpb` first).

        Args:
            date_range: An optional inclusive reporting period (see :meth:`download`);
                returned entries are asserted to fall within it.
            receipt_policy: What to do with the data once received (see
                :class:`~ebicsclient.ReceiptPolicy`).

        Returns:
            The intraday reports the bank delivered, in document order.

        Raises:
            ClientStateError: the bank's keys have not been fetched yet (run HPB first).
            TransportError: a request could not be delivered.
            ProtocolError: a response could not be parsed.
            ReturnCodeError: the bank reported a non-OK return code (e.g. no data available).
            CryptoError: the order data could not be decrypted.
            DateRangeMismatchError: a returned entry falls outside ``date_range``.
            MessageFormatError: the downloaded camt.052 data could not be parsed (the
                download is left un-acknowledged).
            MessageVersionMismatchError: under ``VersionPolicy.STRICT``, the bank
                delivered another message version (the download is left
                un-acknowledged).
        """
        return self._download_parsed(
            CAMT_052,
            camt052.parse,
            date_range=date_range,
            receipt_policy=receipt_policy,
            check=_entries_in_range_check(date_range) if date_range else None,
        )

    def download_booking_advices(
        self,
        btf: BusinessTransactionFormat = CAMT_054,
        *,
        date_range: DateRange | None = None,
        receipt_policy: ReceiptPolicy = ReceiptPolicy.ACKNOWLEDGE,
    ) -> list[Notification]:
        """Download camt.054 debit/credit notifications (booking advices) and parse them.

        A convenience over :meth:`download` for ``REP/camt.054``. Pass a variant BTF (the
        same tuple with a ``service_option`` such as ``"XQRR"``/``"XSCR"``) for the Swiss
        collective-resolution advices. The bank's keys must already be available (call
        :meth:`hpb` first).

        Args:
            btf: The camt.054 Business Transaction Format; defaults to the plain ``CAMT_054``.
            date_range: An optional inclusive reporting period (see :meth:`download`);
                returned entries are asserted to fall within it.
            receipt_policy: What to do with the data once received (see
                :class:`~ebicsclient.ReceiptPolicy`).

        Returns:
            The notifications the bank delivered, in document order.

        Raises:
            ClientStateError: the bank's keys have not been fetched yet (run HPB first).
            TransportError: a request could not be delivered.
            ProtocolError: a response could not be parsed.
            ReturnCodeError: the bank reported a non-OK return code (e.g. no data available).
            CryptoError: the order data could not be decrypted.
            DateRangeMismatchError: a returned entry falls outside ``date_range``.
            MessageFormatError: the downloaded camt.054 data could not be parsed (the
                download is left un-acknowledged).
            MessageVersionMismatchError: under ``VersionPolicy.STRICT``, the bank
                delivered another message version (the download is left
                un-acknowledged).
        """
        return self._download_parsed(
            btf,
            camt054.parse,
            date_range=date_range,
            receipt_policy=receipt_policy,
            check=_entries_in_range_check(date_range) if date_range else None,
        )

    def download_payment_status_reports(
        self,
        *,
        date_range: DateRange | None = None,
        receipt_policy: ReceiptPolicy = ReceiptPolicy.ACKNOWLEDGE,
    ) -> list[PaymentStatusReport]:
        """Download the pain.002 payment status reports and parse them.

        A convenience over :meth:`download` for the common case: it fetches
        ``PSR/pain.002`` and returns the parsed reports — the bank's verdicts on
        previously uploaded pain.001 files, including per-transaction rejections.
        The bank's keys must already be available (call :meth:`hpb` first).

        Args:
            date_range: An optional inclusive reporting period (see :meth:`download`). Unlike
                the camt downloads, no per-entry range check is applied — a pain.002 carries
                payment statuses, not dated booking entries.
            receipt_policy: What to do with the data once received (see
                :class:`~ebicsclient.ReceiptPolicy`).

        Returns:
            The payment status reports the bank delivered, in document order.

        Raises:
            ClientStateError: the bank's keys have not been fetched yet (run HPB first).
            TransportError: a request could not be delivered.
            ProtocolError: a response could not be parsed.
            ReturnCodeError: the bank reported a non-OK return code (e.g. no data available).
            CryptoError: the order data could not be decrypted.
            MessageFormatError: the downloaded pain.002 data could not be parsed (the
                download is left un-acknowledged).
            MessageVersionMismatchError: under ``VersionPolicy.STRICT``, the bank
                delivered another message version (the download is left
                un-acknowledged).
        """
        return self._download_parsed(
            PAIN_002, pain002.parse, date_range=date_range, receipt_policy=receipt_policy
        )

    def upload(self, btf: BusinessTransactionFormat, order_data: bytes) -> str:
        """Upload order data for a Business Transaction Format and return the transaction ID.

        Runs the full upload transaction: it signs and encrypts the order data, opens the
        transaction (initialisation), then sends every segment (transfer). The bank's keys
        must already be available (call :meth:`hpb` first).

        Args:
            btf: The Business Transaction Format to upload (e.g. ``PAIN_001``).
            order_data: The order data to upload (e.g. a pain.001 document as bytes).

        Returns:
            The bank-issued transaction ID for the upload.

        Raises:
            ClientStateError: the bank's keys have not been fetched yet (run HPB first).
            TransportError: a request could not be delivered.
            ProtocolError: a response could not be parsed.
            ReturnCodeError: the bank rejected the upload (e.g. a bad signature or order data).
            CryptoError: the order data could not be signed or encrypted.
        """
        if not isinstance(order_data, bytes | bytearray):
            # A str here would fail deep inside compression with an opaque error; and
            # implicitly encoding it could silently alter the document. The caller owns
            # the encoding: read the file in binary mode or encode it explicitly.
            raise TypeError(
                f"order_data must be bytes, got {type(order_data).__name__} — read the "
                f"file in binary mode ('rb') or use .encode() on an XML string"
            )
        bank_keys = self._require_bank_keys("Upload")
        logger.info("Upload: opening a %s/%s transaction", btf.service_name, btf.message_name)
        payload = h005.prepare_upload(self._user, self._keyring, bank_keys, order_data)
        request = h005.build_upload_initialisation_request(
            self._bank, self._user, self._keyring, bank_keys, btf, payload
        )
        transaction_id = h005.parse_upload_initialisation_response(
            self._post_verified(request, bank_keys)
        )

        segments = payload.order_data_segments
        for number, segment_data in enumerate(segments, start=1):
            transfer = h005.build_upload_transfer_request(
                self._bank,
                self._keyring,
                transaction_id,
                number,
                segment_data,
                last_segment=number == len(segments),
            )
            h005.parse_upload_transfer_response(self._post_verified(transfer, bank_keys))
        logger.info(
            "Upload: sent %d segment(s) for transaction %s", len(segments), transaction_id
        )
        return transaction_id

    def change_keys(
        self,
        new_keyring: Keyring,
        rotation: KeyRotation,
        *,
        certificate_provider: CertificateProvider | None = None,
    ) -> str:
        """Replace subscriber keys at the bank (PUB, HCA, or HCS) and switch this client to them.

        Sends the key change as the EBICS 3.0 order type for ``rotation`` — ``PUB`` for the
        signature key, ``HCA`` for the authentication and encryption keys, ``HCS`` for all
        three (spec 4.6.1). No initialisation letter is needed: the order is signed with the
        *current* A006 key and authenticated with the *current* X002 key, and the bank
        switches as soon as it has processed it. Only then does this client adopt
        ``new_keyring`` (see :attr:`keyring`); on any failure it keeps the current keys.

        The library never touches your stored keyring, so persist the successor **before**
        sending — once the bank has switched, the old keys no longer work, and a successor
        lost to a crash would lock the subscriber out::

            successor = rotate_keyring(client.keyring, KeyRotation.ALL)
            save_keyring(successor, "keyring.next.json", passphrase)  # 1. new keys safe first
            client.change_keys(successor, KeyRotation.ALL)            # 2. the bank switches
            os.replace("keyring.next.json", "keyring.json")           # 3. promote atomically

        If step 2 raises :class:`~ebicsclient.errors.KeyChangeUnconfirmedError`, keep both
        files and establish which keys the bank holds. Any other error means the bank kept
        the old keys: delete the successor file and carry on with the current keyring.

        Args:
            new_keyring: The successor keyring (from :func:`~ebicsclient.rotate_keyring`):
                new keys for the ones ``rotation`` replaces, the others unchanged.
            rotation: Which keys to replace.
            certificate_provider: Supplies the certificates for the new keys; defaults to
                this client's provider. Pass one with the new CA-issued certificates for the
                "mit Zertifikaten" profile — it then replaces the client's provider once the
                change succeeds.

        Returns:
            The bank-issued transaction ID of the key-change upload.

        Raises:
            ClientStateError: the bank's keys have not been fetched yet (run HPB first).
            TypeError: ``new_keyring`` is not a Keyring or ``rotation`` not a KeyRotation.
            ValueError: ``new_keyring`` does not replace exactly the keys ``rotation`` covers.
            KeyringError: a new key is shorter than 2048 bits.
            CertificateError: the certificate provider has no certificate for a new key.
            TransportError: a request before the final segment could not be delivered (the
                bank cannot have processed the change).
            ProtocolError: a response before the final segment could not be parsed or
                verified.
            ReturnCodeError: the bank rejected the key change; it keeps the old keys.
            KeyChangeUnconfirmedError: the final segment was sent but its outcome could not
                be confirmed; the bank may hold either keyring.
        """
        bank_keys = self._require_bank_keys("Key change")
        keys.validate_key_change(self._keyring, new_keyring, rotation)
        provider = (
            certificate_provider if certificate_provider is not None else self._certificate_provider
        )
        order_type = h005.key_change_order_type(rotation)
        order_data = h005.build_key_change_order_data(self._user, new_keyring, rotation, provider)
        # Spec 4.6.1.1: the subscriber's ES over the key-change order data is made with the
        # signature key that is active now — the current keyring, never the successor.
        payload = h005.prepare_upload(self._user, self._keyring, bank_keys, order_data)
        logger.info("%s: opening a key change for user %s", order_type, self._user.user_id)
        request = h005.build_key_change_initialisation_request(
            self._bank, self._user, self._keyring, bank_keys, rotation, payload
        )
        transaction_id = h005.parse_upload_initialisation_response(
            self._post_verified(request, bank_keys)
        )
        self._transfer_key_change(order_type, transaction_id, payload, bank_keys)

        self._keyring = new_keyring
        if certificate_provider is not None:
            self._certificate_provider = certificate_provider
        logger.info(
            "%s: the bank accepted the key change (transaction %s); the client now uses the "
            "new keys",
            order_type,
            transaction_id,
        )
        return transaction_id

    def _transfer_key_change(
        self, order_type: str, transaction_id: str, payload: UploadPayload, bank_keys: BankKeys
    ) -> None:
        segments = payload.order_data_segments
        for number, segment_data in enumerate(segments, start=1):
            last_segment = number == len(segments)
            transfer = h005.build_upload_transfer_request(
                self._bank,
                self._keyring,
                transaction_id,
                number,
                segment_data,
                last_segment=last_segment,
            )
            if not last_segment:
                # The bank processes the order only once it has the last segment, so a
                # failure here leaves the old keys in force: let it propagate as is.
                h005.parse_upload_transfer_response(self._post_verified(transfer, bank_keys))
                continue
            # The bank processes the change before answering the final segment (spec 4.3),
            # so that answer is authoritative: a verified rejection means the old keys stay.
            # Anything short of a verified answer leaves the outcome open.
            try:
                h005.parse_upload_transfer_response(self._post_verified(transfer, bank_keys))
            except UnknownReturnCodeError as error:
                raise KeyChangeUnconfirmedError(order_type, transaction_id) from error
            except ReturnCodeError:
                raise
            except EbicsError as error:
                raise KeyChangeUnconfirmedError(order_type, transaction_id) from error
