"""Features not yet validated against a bank — use them knowing that.

The regular ``ebicsclient`` API only holds what has run against a real bank or a bank's
test platform. What is implemented to the standard, or registered at a bank, but has not
yet passed such a test lives here instead, so it can reach the people able to test it
without the library claiming more than it knows. Each item says what is verified and what
is not.

Nothing in this module is exported from ``ebicsclient`` itself, and its contents may change
or move without a deprecation period: an item moves to the regular API once it passes a
live test, and is dropped if it fails one. The verification status of every item is in
docs/12-verification-ledger.md and docs/13-standard-conformance.md.
"""

from ebicsclient.models import BusinessTransactionFormat

#: The pain.001.001.09 SEPA payment-submission upload (the ZKB ``CCT`` order type,
#: ``SCT / pain.001 / 09``, no container), for SEPA credit transfers: EUR, service level
#: ``SEPA``, the creditor's IBAN.
#:
#: Verified: the tuple matches the ZKB test subscriber's HTD registry, which registers it
#: without the ``GLB`` scope that ZKB's catalogue shows, and the upload request validates
#: against the H005 schema. Not verified: processing. The ZKB test platform answers an upload
#: under this BTF with ``000000`` and then never processes it (no pain.002, no booking): its
#: customer acknowledgement (HAC) logs the signature check as ``TD03`` IncorrectFileStructure.
#: The same file is processed under ``PAIN_001`` and ``PAIN_001_CGI`` (docs/09). At ZKB, send
#: SEPA payments through one of those two.
PAIN_001_SEPA = BusinessTransactionFormat(
    service_name="SCT",
    message_name="pain.001",
    message_version="09",
)

__all__ = ["PAIN_001_SEPA"]
