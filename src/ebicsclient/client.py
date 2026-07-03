"""High-level EBICS client orchestration.

Ties the keyring, protocol envelopes, and transport together into the operations a
caller performs: the key-initialisation handshake (INI, HIA) and — once activated —
fetching the bank's keys (HPB) and downloading statements.
"""

import logging

from ebicsclient import letter
from ebicsclient.errors import ReturnCodeError
from ebicsclient.models import (
    Bank,
    BankKeys,
    InitializationState,
    Keyring,
    Letter,
    OutputFormat,
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
    ) -> None:
        """Configure the client.

        Args:
            bank: The target bank.
            user: The subscriber's identifiers.
            keyring: The subscriber's key pairs.
            transport: Transport to use; defaults to an HTTPS transport for ``bank.url``.
        """
        self._bank = bank
        self._user = user
        self._keyring = keyring
        self._transport = transport if transport is not None else Transport(bank.url)
        self._bank_keys: BankKeys | None = None

    @property
    def bank_keys(self) -> BankKeys | None:
        """The bank's public keys once HPB has run, or ``None`` before then."""
        return self._bank_keys

    def make_ini_letter(self, *, output_format: OutputFormat = OutputFormat.AUTO) -> Letter:
        """Render the initialisation letter to print, sign, and send to the bank.

        The letter carries the subscriber's public-key hashes so the bank can verify, out
        of band, the keys it received electronically over INI and HIA.

        Args:
            output_format: The output format. ``AUTO`` renders PDF when the optional
                ``pdf`` extra is installed, otherwise HTML.

        Returns:
            The rendered letter (format, media type, and content bytes).

        Raises:
            MissingDependencyError: PDF output was requested without the ``pdf`` extra.
        """
        return letter.make_ini_letter(
            self._bank, self._user, self._keyring, output_format=output_format
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
        request = h005.build_ini_request(self._bank, self._user, self._keyring)
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
        request = h005.build_hia_request(self._bank, self._user, self._keyring)
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

    def hpb(self) -> BankKeys:
        """Send HPB — download, store, and return the bank's public keys.

        Sends a signed HPB request, decrypts the response with the E002 key, and stores
        the bank's authentication (X002) and encryption (E002) public keys on the client
        (also available via :attr:`bank_keys`). Verify their hashes against the values the
        bank publishes out of band before trusting them.

        Returns:
            The bank's public keys.

        Raises:
            TransportError: the request could not be delivered.
            ProtocolError: the response could not be parsed.
            ReturnCodeError: the bank rejected the request.
            CryptoError: the response could not be decrypted.
        """
        logger.info("HPB: requesting the bank's public keys from host %s", self._bank.host_id)
        request = h005.build_hpb_request(self._bank, self._user, self._keyring)
        authentication, encryption = h005.parse_hpb_response(
            self._transport.post(request), self._keyring
        )
        self._bank_keys = BankKeys(authentication=authentication, encryption=encryption)
        return self._bank_keys
