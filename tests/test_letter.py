"""Tests for ebicsclient.letter: the EBICS 3.0 INI/HIA initialisation letters.

EBICS 3.0 (spec sections 4.4.1.2.3 and 11.5) defines the letters' content: the INI
letter carries the A006 signature certificate, the HIA letter the X002 authentication
and E002 encryption certificates — each as PEM plus the SHA-256 hash of the DER-encoded
certificate in uppercase hexadecimal. The bank compares those hashes against the
certificates INI/HIA transmitted, so the letter must reproduce exactly those
certificates.
"""

import datetime
import re
import sys

import pytest

from ebicsclient import keys, letter
from ebicsclient.errors import MissingDependencyError
from ebicsclient.keys import CertificateUsage, certificate_fingerprint
from ebicsclient.models import Bank, Keyring, OutputFormat, User


@pytest.fixture(scope="module")
def bank() -> Bank:
    return Bank(host_id="ZKBKCHZZ", url="https://ebicsweb.example.com/ebicsweb")


@pytest.fixture(scope="module")
def user() -> User:
    return User(partner_id="PARTNER1", user_id="USER1")


@pytest.fixture(scope="module")
def keyring() -> Keyring:
    return keys.generate_keyring()


def _certificate_hash(keyring: Keyring, usage: CertificateUsage, user: User) -> str:
    # The hash the bank compares: SHA-256 over the DER of the very certificate INI/HIA
    # sends — regenerated here exactly as the default provider does.
    private_key = getattr(keyring, usage.value)
    certificate = keys.generate_self_signed_certificate(private_key, user.user_id, usage)
    return " ".join(f"{byte:02X}" for byte in certificate_fingerprint(certificate))


def test_html_letter_carries_ids_versions_and_certificate_hashes(
    bank: Bank, user: User, keyring: Keyring
) -> None:
    result = letter.make_ini_letter(
        bank,
        user,
        keyring,
        output_format=OutputFormat.HTML,
        created=datetime.datetime(2026, 6, 30, 12, 34, 56, tzinfo=datetime.UTC),
    )
    assert result.output_format is OutputFormat.HTML
    assert result.media_type == "text/html; charset=utf-8"
    text = result.content.decode("utf-8")
    assert "<!DOCTYPE html>" in text
    assert bank.host_id in text
    assert user.partner_id in text
    assert user.user_id in text
    assert "2026-06-30" in text
    assert "12:34:56" in text
    # Both letters are present, each with its order type.
    assert "EBICS Initialisation Letter (INI)" in text
    assert "EBICS Initialisation Letter (HIA)" in text
    for version in ("A006", "X002", "E002"):
        assert version in text
    # The EBICS 3.0 letter hash: SHA-256 over the certificate DER, per certificate.
    for usage in CertificateUsage:
        assert _certificate_hash(keyring, usage, user) in text


def test_html_letter_embeds_the_certificates_in_pem(
    bank: Bank, user: User, keyring: Keyring
) -> None:
    text = letter.make_ini_letter(
        bank, user, keyring, output_format=OutputFormat.HTML
    ).content.decode("utf-8")
    # The spec presents each certificate in PEM format on the letter.
    assert text.count("BEGIN CERTIFICATE") == 3


def test_letter_hashes_are_stable_across_renderings(
    bank: Bank, user: User, keyring: Keyring
) -> None:
    # Certificates are deterministic, so two independently rendered letters print the
    # same fingerprints — the property that lets a letter printed today match an INI/HIA
    # sent in an earlier session.
    first = letter.make_ini_letter(
        bank, user, keyring, output_format=OutputFormat.HTML
    ).content.decode("utf-8")
    second = letter.make_ini_letter(
        bank, user, keyring, output_format=OutputFormat.HTML
    ).content.decode("utf-8")
    pattern = re.compile(r'<p class="hex">([0-9A-F ]+)</p>')
    assert pattern.findall(first) == pattern.findall(second)
    assert len(pattern.findall(first)) == 3


def test_html_escapes_identifiers(bank: Bank, keyring: Keyring) -> None:
    user = User(partner_id="A&B", user_id="<u>")
    text = letter.make_ini_letter(
        bank, user, keyring, output_format=OutputFormat.HTML
    ).content.decode("utf-8")
    assert "A&amp;B" in text
    assert "&lt;u&gt;" in text


def test_auto_falls_back_to_html_without_reportlab(
    bank: Bank, user: User, keyring: Keyring, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(letter, "_pdf_available", lambda: False)
    result = letter.make_ini_letter(bank, user, keyring, output_format=OutputFormat.AUTO)
    assert result.output_format is OutputFormat.HTML


def test_auto_renders_pdf_when_reportlab_is_available(
    bank: Bank, user: User, keyring: Keyring, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("reportlab")
    monkeypatch.setattr(letter, "_pdf_available", lambda: True)
    result = letter.make_ini_letter(bank, user, keyring, output_format=OutputFormat.AUTO)
    assert result.output_format is OutputFormat.PDF
    assert result.media_type == "application/pdf"
    assert result.content.startswith(b"%PDF")


def test_explicit_pdf_renders_a_pdf(bank: Bank, user: User, keyring: Keyring) -> None:
    pytest.importorskip("reportlab")
    result = letter.make_ini_letter(bank, user, keyring, output_format=OutputFormat.PDF)
    assert result.output_format is OutputFormat.PDF
    assert result.content.startswith(b"%PDF")


def test_pdf_renders_the_ini_and_hia_letters_on_separate_pages(
    bank: Bank, user: User, keyring: Keyring
) -> None:
    pytest.importorskip("reportlab")
    content = letter.make_ini_letter(bank, user, keyring, output_format=OutputFormat.PDF).content
    # One page per letter: INI and HIA.
    assert re.findall(rb"/Count (\d+)", content) == [b"2"]


def test_html_shows_the_default_branding(bank: Bank, user: User, keyring: Keyring) -> None:
    text = letter.make_ini_letter(
        bank, user, keyring, output_format=OutputFormat.HTML
    ).content.decode("utf-8")
    assert "Generated with ebicsClient" in text


def test_branding_is_configurable_and_escaped(bank: Bank, user: User, keyring: Keyring) -> None:
    text = letter.make_ini_letter(
        bank, user, keyring, output_format=OutputFormat.HTML, branding="Acme & Co"
    ).content.decode("utf-8")
    assert "Generated with Acme &amp; Co" in text


def test_explicit_pdf_without_reportlab_raises(
    bank: Bank, user: User, keyring: Keyring, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Make every reportlab import fail, whether or not it is installed: a None entry in
    # sys.modules causes "import reportlab..." to raise ImportError.
    for name in [n for n in sys.modules if n == "reportlab" or n.startswith("reportlab.")]:
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.setitem(sys.modules, "reportlab", None)
    with pytest.raises(MissingDependencyError) as caught:
        letter.make_ini_letter(bank, user, keyring, output_format=OutputFormat.PDF)
    assert caught.value.extra == "pdf"
