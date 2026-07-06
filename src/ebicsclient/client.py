"""High-level EBICS client orchestration.

Ties the keyring, protocol envelopes, and transport together into the operations a
caller performs: the key-initialisation handshake (INI, HIA) and — once activated —
fetching the bank's keys (HPB) and downloading statements.
"""

import base64
import logging

from ebicsclient import crypto, keys, letter
from ebicsclient.certificates import (
    DEFAULT_CERTIFICATE_PROVIDER,
    BankCertificateVerifier,
    CertificateProvider,
)
from ebicsclient.errors import BankKeyMismatchError, ClientStateError, ReturnCodeError
from ebicsclient.formats import camt052, camt053, camt054, pain002
from ebicsclient.models import (
    CAMT_052,
    CAMT_053,
    CAMT_054,
    PAIN_002,
    Bank,
    BankKeyHashes,
    BankKeys,
    BusinessTransactionFormat,
    InitializationState,
    Keyring,
    Letter,
    Notification,
    OutputFormat,
    PaymentStatusReport,
    Statement,
    User,
)
from ebicsclient.protocol import h005
from ebicsclient.transport import Transport

logger = logging.getLogger(__name__)

# EBICS_INVALID_USER_OR_USER_STATE — on a key-submission re-run this means the subscriber
# is already initialised; it is also how the bank reports an unknown subscriber (which then
# surfaces at HPB), so we identify it but do not treat a re-run as a hard failure.
_SUBSCRIBER_STATE_INADMISSIBLE = "091002"


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
        """
        self._bank = bank
        self._user = user
        self._keyring = keyring
        self._transport = transport if transport is not None else Transport(bank.url)
        self._certificate_provider = certificate_provider
        self._bank_certificate_verifier = bank_certificate_verifier
        self._bank_keys: BankKeys | None = None

    @property
    def bank_keys(self) -> BankKeys | None:
        """The bank's public keys once HPB has run, or ``None`` before then."""
        return self._bank_keys

    def make_ini_letter(
        self,
        *,
        output_format: OutputFormat = OutputFormat.AUTO,
        branding: str = "ebicsClient",
    ) -> Letter:
        """Render the initialisation letter to print, sign, and send to the bank.

        The letter carries the subscriber's public-key hashes so the bank can verify, out
        of band, the keys it received electronically over INI and HIA.

        Args:
            output_format: The output format. ``AUTO`` renders PDF when the optional
                ``pdf`` extra is installed, otherwise HTML.
            branding: A name shown in the letter's footer; defaults to ``"ebicsClient"``.

        Returns:
            The rendered letter (format, media type, and content bytes).

        Raises:
            MissingDependencyError: PDF output was requested without the ``pdf`` extra.
        """
        return letter.make_ini_letter(
            self._bank,
            self._user,
            self._keyring,
            output_format=output_format,
            branding=branding,
        )

    def ini(self) -> InitializationState:
        """Send INI — submit the signature public key (A006) to the bank.

        Idempotent: if the subscriber is already initialised the bank rejects the re-run
        (return code ``091002``), which is reported as ``ALREADY_INITIALISED`` rather than
        raised.

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

        Idempotent in the same way as :meth:`ini`.

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
                logger.info(
                    "%s: subscriber %s already initialised — %s",
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

    def download(self, btf: BusinessTransactionFormat) -> bytes:
        """Download order data for a Business Transaction Format and return the plaintext.

        Runs the full download transaction: it opens the transaction (initialisation),
        fetches every further segment (transfer), acknowledges the transfer (receipt), then
        reassembles, decrypts, and inflates the order data. The bank's keys must already be
        available (call :meth:`hpb` first).

        Args:
            btf: The Business Transaction Format to download (e.g. ``CAMT_053``).

        Returns:
            The decrypted, decompressed order-data bytes. For a container format this is the
            container itself — e.g. ``CAMT_053`` yields a ZIP of camt.053 documents.

        Raises:
            ClientStateError: the bank's keys have not been fetched yet (run HPB first).
            TransportError: a request could not be delivered.
            ProtocolError: a response could not be parsed.
            ReturnCodeError: the bank reported a non-OK return code (e.g. no data available).
            CryptoError: the order data could not be decrypted.
        """
        if self._bank_keys is None:
            raise ClientStateError("Download requires the bank's keys; call hpb() first")
        logger.info("Download: opening a %s/%s transaction", btf.service_name, btf.message_name)
        request = h005.build_download_initialisation_request(
            self._bank, self._user, self._keyring, self._bank_keys, btf
        )
        initialisation = h005.parse_download_initialisation_response(self._transport.post(request))

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
            segment = h005.parse_download_segment_response(self._transport.post(transfer))
            segments.append(segment.order_data_segment)

        # Acknowledge the completed transfer so the bank marks the download as delivered.
        # The bank answers with 011000 EBICS_DOWNLOAD_POSTPROCESS_DONE — a success code.
        receipt = h005.build_download_receipt_request(
            self._bank, self._keyring, initialisation.transaction_id
        )
        h005.parse_download_receipt_response(self._transport.post(receipt))
        logger.info(
            "Download: received %d segment(s) for transaction %s",
            initialisation.num_segments,
            initialisation.transaction_id,
        )

        # The segments are pieces of a single base64 stream, so join before decoding — a
        # segment boundary need not fall on a 4-character base64 group.
        encrypted_order_data = base64.b64decode("".join(segments))
        return crypto.decrypt_order_data(
            self._keyring.encryption, initialisation.transaction_key, encrypted_order_data
        )

    def download_statements(self) -> list[Statement]:
        """Download the end-of-period camt.053 statements and parse them.

        A convenience over :meth:`download` for the common case: it fetches
        ``EOP/camt.053`` and returns the parsed statements (account, balances, entries).
        The bank's keys must already be available (call :meth:`hpb` first).

        Returns:
            The account statements the bank delivered, in document order.

        Raises:
            ClientStateError: the bank's keys have not been fetched yet (run HPB first).
            TransportError: a request could not be delivered.
            ProtocolError: a response could not be parsed.
            ReturnCodeError: the bank reported a non-OK return code (e.g. no data available).
            CryptoError: the order data could not be decrypted.
            MessageFormatError: the downloaded camt.053 data could not be parsed.
        """
        return camt053.parse(self.download(CAMT_053))

    def download_intraday_statements(self) -> list[Statement]:
        """Download the intraday camt.052 account reports and parse them.

        A convenience over :meth:`download` for ``STM/camt.052``. Intraday reports share
        the statement shape; interim balances (if any) are in ``balances`` rather than
        ``opening_balance``/``closing_balance``. The bank's keys must already be available
        (call :meth:`hpb` first).

        Returns:
            The intraday reports the bank delivered, in document order.

        Raises:
            ClientStateError: the bank's keys have not been fetched yet (run HPB first).
            TransportError: a request could not be delivered.
            ProtocolError: a response could not be parsed.
            ReturnCodeError: the bank reported a non-OK return code (e.g. no data available).
            CryptoError: the order data could not be decrypted.
            MessageFormatError: the downloaded camt.052 data could not be parsed.
        """
        return camt052.parse(self.download(CAMT_052))

    def download_booking_advices(
        self, btf: BusinessTransactionFormat = CAMT_054
    ) -> list[Notification]:
        """Download camt.054 debit/credit notifications (booking advices) and parse them.

        A convenience over :meth:`download` for ``REP/camt.054``. Pass a variant BTF (the
        same tuple with a ``service_option`` such as ``"XQRR"``/``"XSCR"``) for the Swiss
        collective-resolution advices. The bank's keys must already be available (call
        :meth:`hpb` first).

        Args:
            btf: The camt.054 Business Transaction Format; defaults to the plain ``CAMT_054``.

        Returns:
            The notifications the bank delivered, in document order.

        Raises:
            ClientStateError: the bank's keys have not been fetched yet (run HPB first).
            TransportError: a request could not be delivered.
            ProtocolError: a response could not be parsed.
            ReturnCodeError: the bank reported a non-OK return code (e.g. no data available).
            CryptoError: the order data could not be decrypted.
            MessageFormatError: the downloaded camt.054 data could not be parsed.
        """
        return camt054.parse(self.download(btf))

    def download_payment_status_reports(self) -> list[PaymentStatusReport]:
        """Download the pain.002 payment status reports and parse them.

        A convenience over :meth:`download` for the common case: it fetches
        ``PSR/pain.002`` and returns the parsed reports — the bank's verdicts on
        previously uploaded pain.001 files, including per-transaction rejections.
        The bank's keys must already be available (call :meth:`hpb` first).

        Returns:
            The payment status reports the bank delivered, in document order.

        Raises:
            ClientStateError: the bank's keys have not been fetched yet (run HPB first).
            TransportError: a request could not be delivered.
            ProtocolError: a response could not be parsed.
            ReturnCodeError: the bank reported a non-OK return code (e.g. no data available).
            CryptoError: the order data could not be decrypted.
            MessageFormatError: the downloaded pain.002 data could not be parsed.
        """
        return pain002.parse(self.download(PAIN_002))

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
        if self._bank_keys is None:
            raise ClientStateError("Upload requires the bank's keys; call hpb() first")
        logger.info("Upload: opening a %s/%s transaction", btf.service_name, btf.message_name)
        payload = h005.prepare_upload(self._user, self._keyring, self._bank_keys, order_data)
        request = h005.build_upload_initialisation_request(
            self._bank, self._user, self._keyring, self._bank_keys, btf, payload
        )
        transaction_id = h005.parse_upload_initialisation_response(self._transport.post(request))

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
            h005.parse_upload_transfer_response(self._transport.post(transfer))
        logger.info(
            "Upload: sent %d segment(s) for transaction %s", len(segments), transaction_id
        )
        return transaction_id
