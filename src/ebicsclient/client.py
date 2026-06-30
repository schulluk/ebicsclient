"""High-level EBICS client orchestration.

Ties the keyring, protocol envelopes, and transport together into the operations a
caller performs: the key-initialisation handshake (INI, HIA) and — once activated —
fetching the bank's keys (HPB) and downloading statements.
"""

import logging

from ebicsclient.models import Bank, Keyring, User
from ebicsclient.protocol import h005
from ebicsclient.transport import Transport

logger = logging.getLogger(__name__)


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

    def ini(self) -> None:
        """Send INI — submit the signature public key (A006) to the bank.

        Raises:
            TransportError: the request could not be delivered.
            ProtocolError: the response could not be parsed.
            ReturnCodeError: the bank rejected the submission.
        """
        logger.info("INI: submitting the signature key for user %s", self._user.user_id)
        request = h005.build_ini_request(self._bank, self._user, self._keyring)
        h005.raise_for_return_code(self._transport.post(request))

    def hia(self) -> None:
        """Send HIA — submit the authentication (X002) and encryption (E002) public keys.

        Raises:
            TransportError: the request could not be delivered.
            ProtocolError: the response could not be parsed.
            ReturnCodeError: the bank rejected the submission.
        """
        logger.info(
            "HIA: submitting the authentication and encryption keys for user %s", self._user.user_id
        )
        request = h005.build_hia_request(self._bank, self._user, self._keyring)
        h005.raise_for_return_code(self._transport.post(request))
