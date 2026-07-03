"""Tests for ebicsclient.letter: HTML and PDF initialisation-letter rendering."""

import datetime
import re
import sys

import pytest

from ebicsclient import keys, letter
from ebicsclient.errors import MissingDependencyError
from ebicsclient.keys import public_key_hash
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


def _grouped_hash(keyring: Keyring) -> str:
    digest = public_key_hash(keyring.signature.public_key())
    return " ".join(f"{byte:02X}" for byte in digest)


def test_html_letter_carries_ids_versions_and_hashes(
    bank: Bank, user: User, keyring: Keyring
) -> None:
    result = letter.make_ini_letter(
        bank, user, keyring, output_format=OutputFormat.HTML, created=datetime.date(2026, 6, 30)
    )
    assert result.output_format is OutputFormat.HTML
    assert result.media_type == "text/html; charset=utf-8"
    text = result.content.decode("utf-8")
    assert "<!DOCTYPE html>" in text
    assert bank.host_id in text
    assert user.partner_id in text
    assert user.user_id in text
    assert "2026-06-30" in text
    for version in ("A006", "X002", "E002"):
        assert version in text
    assert _grouped_hash(keyring) in text


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


def test_pdf_letter_fits_on_a_single_page(bank: Bank, user: User, keyring: Keyring) -> None:
    pytest.importorskip("reportlab")
    content = letter.make_ini_letter(bank, user, keyring, output_format=OutputFormat.PDF).content
    assert re.findall(rb"/Count (\d+)", content) == [b"1"]


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
