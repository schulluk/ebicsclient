"""Initialisation-letter rendering.

After generating a keyring, the subscriber sends the bank a signed initialisation letter
carrying the public keys' hashes, so the bank can verify out of band the keys it received
electronically over INI and HIA. This module renders that letter from the keyring as
printable HTML (always available, no extra dependency) or as PDF (the optional ``pdf``
extra, backed by reportlab).

The same key facts drive both formats: for each of the three keys (A006 signature, X002
authentication, E002 encryption) the letter shows the public exponent and modulus and the
EBICS SHA-256 public-key hash, all as space-grouped uppercase hexadecimal — the form a
person can read aloud or compare digit by digit.
"""

import datetime
import html
import importlib.util
import io
from dataclasses import dataclass
from string import Template

from cryptography.hazmat.primitives.asymmetric import rsa

from ebicsclient.errors import MissingDependencyError
from ebicsclient.keys import public_key_hash
from ebicsclient.models import Bank, Keyring, Letter, OutputFormat, User

_HASH_ALGORITHM = "SHA-256"


@dataclass(frozen=True, slots=True)
class _KeyPanel:
    """The displayable facts for one key, pre-formatted for either output format."""

    title: str
    version: str
    exponent: str
    modulus: str
    digest: str


def make_ini_letter(
    bank: Bank,
    user: User,
    keyring: Keyring,
    *,
    output_format: OutputFormat = OutputFormat.AUTO,
    created: datetime.date | None = None,
) -> Letter:
    """Render the initialisation letter for a subscriber's keyring.

    Args:
        bank: The target bank (its Host ID appears on the letter).
        user: The subscriber whose public-key hashes the letter certifies.
        keyring: The subscriber's key pairs.
        output_format: The output format. ``AUTO`` renders PDF when the optional ``pdf``
            extra is installed, otherwise HTML.
        created: The date printed on the letter; defaults to today.

    Returns:
        The rendered letter (its concrete format, media type, and content bytes).

    Raises:
        MissingDependencyError: PDF output was requested but the ``pdf`` extra is absent.
    """
    resolved = _resolve_format(output_format)
    when = created if created is not None else datetime.date.today()
    panels = _key_panels(keyring)
    if resolved is OutputFormat.HTML:
        content = _render_html(bank, user, panels, when)
        return Letter(
            output_format=OutputFormat.HTML, media_type="text/html; charset=utf-8", content=content
        )
    if resolved is OutputFormat.PDF:
        content = _render_pdf(bank, user, panels, when)
        return Letter(
            output_format=OutputFormat.PDF, media_type="application/pdf", content=content
        )
    # _resolve_format only ever returns a concrete format.
    raise AssertionError(f"Unexpected output format: {resolved}")


def _resolve_format(output_format: OutputFormat) -> OutputFormat:
    if output_format is OutputFormat.AUTO:
        return OutputFormat.PDF if _pdf_available() else OutputFormat.HTML
    return output_format


def _pdf_available() -> bool:
    return importlib.util.find_spec("reportlab") is not None


def _key_panels(keyring: Keyring) -> list[_KeyPanel]:
    return [
        _key_panel("Bank-technical signature key (INI)", "A006", keyring.signature.public_key()),
        _key_panel(
            "Identification and authentication key (HIA)",
            "X002",
            keyring.authentication.public_key(),
        ),
        _key_panel("Encryption key (HIA)", "E002", keyring.encryption.public_key()),
    ]


def _key_panel(title: str, version: str, public_key: rsa.RSAPublicKey) -> _KeyPanel:
    numbers = public_key.public_numbers()
    return _KeyPanel(
        title=title,
        version=version,
        exponent=_grouped_hex_int(numbers.e),
        modulus=_grouped_hex_int(numbers.n),
        digest=_grouped_hex_bytes(public_key_hash(public_key)),
    )


def _grouped_hex_int(value: int) -> str:
    raw = format(value, "X")
    if len(raw) % 2:
        raw = "0" + raw
    return _grouped_hex_bytes(bytes.fromhex(raw))


def _grouped_hex_bytes(data: bytes) -> str:
    return " ".join(f"{byte:02X}" for byte in data)


def _render_html(bank: Bank, user: User, panels: list[_KeyPanel], created: datetime.date) -> bytes:
    sections = "\n".join(
        _HTML_PANEL.substitute(
            title=html.escape(panel.title),
            version=html.escape(panel.version),
            exponent=html.escape(panel.exponent),
            modulus=html.escape(panel.modulus),
            digest=html.escape(panel.digest),
            hash_algorithm=_HASH_ALGORITHM,
        )
        for panel in panels
    )
    document = _HTML_DOCUMENT.substitute(
        host_id=html.escape(bank.host_id),
        partner_id=html.escape(user.partner_id),
        user_id=html.escape(user.user_id),
        created=html.escape(created.isoformat()),
        panels=sections,
    )
    return document.encode("utf-8")


def _render_pdf(bank: Bank, user: User, panels: list[_KeyPanel], created: datetime.date) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    except ImportError as error:
        raise MissingDependencyError("PDF letter output", "pdf") from error

    styles = getSampleStyleSheet()
    label = styles["Normal"]
    hex_style = ParagraphStyle("hex", parent=styles["Code"], fontSize=7, leading=9)

    story = [
        Paragraph("EBICS Initialisation Letter", styles["Title"]),
        Paragraph(
            "Please verify the public-key hashes below against the keys received "
            "electronically, then sign and return this letter to your bank.",
            label,
        ),
        Spacer(1, 0.4 * cm),
        Paragraph(f"<b>Host ID:</b> {html.escape(bank.host_id)}", label),
        Paragraph(f"<b>Partner ID:</b> {html.escape(user.partner_id)}", label),
        Paragraph(f"<b>User ID:</b> {html.escape(user.user_id)}", label),
        Paragraph(f"<b>Date:</b> {html.escape(created.isoformat())}", label),
        Spacer(1, 0.4 * cm),
    ]
    for panel in panels:
        heading = f"{html.escape(panel.title)} ({html.escape(panel.version)})"
        story.append(Paragraph(heading, styles["Heading2"]))
        story.append(Paragraph("<b>Exponent</b>", label))
        story.append(Paragraph(html.escape(panel.exponent), hex_style))
        story.append(Paragraph("<b>Modulus</b>", label))
        story.append(Paragraph(html.escape(panel.modulus), hex_style))
        story.append(Paragraph(f"<b>{_HASH_ALGORITHM} hash</b>", label))
        story.append(Paragraph(html.escape(panel.digest), hex_style))
        story.append(Spacer(1, 0.3 * cm))

    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph("Place, date: ______________________________", label))
    story.append(Spacer(1, 0.8 * cm))
    story.append(
        Paragraph(f"Signature ({html.escape(user.user_id)}): ______________________________", label)
    )

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title="EBICS Initialisation Letter",
        leftMargin=2.5 * cm,
        rightMargin=2.5 * cm,
        topMargin=2.5 * cm,
        bottomMargin=2.5 * cm,
    )
    document.build(story)
    return buffer.getvalue()


_HTML_PANEL = Template(
    """    <section class="key">
      <h2>$title <span class="version">$version</span></h2>
      <dl>
        <dt>Exponent</dt><dd class="hex">$exponent</dd>
        <dt>Modulus</dt><dd class="hex">$modulus</dd>
        <dt>$hash_algorithm hash</dt><dd class="hex">$digest</dd>
      </dl>
    </section>"""
)

_HTML_DOCUMENT = Template(
    """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>EBICS Initialisation Letter</title>
<style>
  body { font-family: Helvetica, Arial, sans-serif; color: #111; margin: 2.5cm; }
  h1 { font-size: 18pt; }
  h2 { font-size: 12pt; margin-bottom: 0.2em; }
  .version { color: #555; font-weight: normal; }
  dl { margin: 0 0 0.8em 0; }
  dt { font-weight: bold; margin-top: 0.4em; }
  dd { margin: 0; }
  .hex { font-family: "Courier New", monospace; font-size: 9pt; word-break: break-all; }
  table.meta td { padding-right: 1.5em; }
  .sign { margin-top: 2em; }
  .line { border-top: 1px solid #000; width: 8cm; margin-top: 2.5em; padding-top: 0.3em; }
</style>
</head>
<body>
<h1>EBICS Initialisation Letter</h1>
<p>Please verify the public-key hashes below against the keys received electronically,
then sign and return this letter to your bank.</p>
<table class="meta">
  <tr><td><strong>Host ID</strong></td><td>$host_id</td></tr>
  <tr><td><strong>Partner ID</strong></td><td>$partner_id</td></tr>
  <tr><td><strong>User ID</strong></td><td>$user_id</td></tr>
  <tr><td><strong>Date</strong></td><td>$created</td></tr>
</table>
$panels
<div class="sign">
  <div class="line">Place, date</div>
  <div class="line">Signature ($user_id)</div>
</div>
</body>
</html>
"""
)
