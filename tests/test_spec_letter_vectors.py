"""Golden-vector tests for the initialisation-letter hash, from the EBICS 3.0 spec itself.

The EBICS 3.0 specification (Final Version 2017-03-29) publishes example initialisation
letters in sections 11.5.1 (INI) and 11.5.2 (HIA), each with an example certificate and
the hash the letter must print. These are golden vectors **from the authority** — the
strongest offline oracle for the letter-hash computation, and precisely the check that
was missing when the letter shipped with the EBICS 2.x public-key hash instead (the flaw
a real ZKB activation attempt exposed; see docs/12-verification-ledger.md).

Spec, section 4.4.1.2.3: the printed hash is "the SHA2-256 hash value of the certificate
in DER binary format", presented as 64 uppercase hexadecimal characters.
"""

import base64
import json
from pathlib import Path

import pytest
from cryptography import x509

from ebicsclient.keys import certificate_fingerprint

_FIXTURE = Path(__file__).parent / "data" / "ebics30_spec_letter_certificates.json"


def _vectors() -> list[dict[str, str]]:
    payload = json.loads(_FIXTURE.read_text())
    vectors: list[dict[str, str]] = payload["vectors"]
    return vectors


@pytest.mark.parametrize("vector", _vectors(), ids=lambda v: f"{v['letter']}-{v['version']}")
def test_certificate_fingerprint_matches_the_spec_example(vector: dict[str, str]) -> None:
    der = base64.b64decode(vector["certificate_der_base64"])
    certificate = x509.load_der_x509_certificate(der)
    fingerprint = certificate_fingerprint(certificate)
    formatted = " ".join(f"{byte:02X}" for byte in fingerprint)
    assert formatted == vector["expected_sha256"]


def test_the_spec_publishes_one_ini_and_two_hia_vectors() -> None:
    # 11.5.1: the INI letter carries the A006 signature certificate; 11.5.2: the HIA
    # letter carries the X002 authentication and E002 encryption certificates.
    letters = sorted((vector["letter"], vector["version"]) for vector in _vectors())
    assert letters == [("HIA", "E002"), ("HIA", "X002"), ("INI", "A006")]
