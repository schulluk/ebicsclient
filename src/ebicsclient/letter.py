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


_DEFAULT_BRANDING = "ebicsClient"


def make_ini_letter(
    bank: Bank,
    user: User,
    keyring: Keyring,
    *,
    output_format: OutputFormat = OutputFormat.AUTO,
    created: datetime.date | None = None,
    branding: str = _DEFAULT_BRANDING,
) -> Letter:
    """Render the initialisation letter for a subscriber's keyring.

    Args:
        bank: The target bank (its Host ID appears on the letter).
        user: The subscriber whose public-key hashes the letter certifies.
        keyring: The subscriber's key pairs.
        output_format: The output format. ``AUTO`` renders PDF when the optional ``pdf``
            extra is installed, otherwise HTML.
        created: The date printed on the letter; defaults to today.
        branding: A name shown in the letter's footer (e.g. the downstream product name);
            defaults to ``"ebicsClient"``.

    Returns:
        The rendered letter (its concrete format, media type, and content bytes).

    Raises:
        MissingDependencyError: PDF output was requested but the ``pdf`` extra is absent.
    """
    resolved = _resolve_format(output_format)
    when = created if created is not None else datetime.date.today()
    panels = _key_panels(keyring)
    if resolved is OutputFormat.HTML:
        content = _render_html(bank, user, panels, when, branding)
        return Letter(
            output_format=OutputFormat.HTML, media_type="text/html; charset=utf-8", content=content
        )
    if resolved is OutputFormat.PDF:
        content = _render_pdf(bank, user, panels, when, branding)
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


def _render_html(
    bank: Bank, user: User, panels: list[_KeyPanel], created: datetime.date, branding: str
) -> bytes:
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
        branding=html.escape(branding),
        panels=sections,
    )
    return document.encode("utf-8")


def _render_pdf(
    bank: Bank, user: User, panels: list[_KeyPanel], created: datetime.date, branding: str
) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            KeepTogether,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as error:
        raise MissingDependencyError("PDF letter output", "pdf") from error

    styles = getSampleStyleSheet()
    label = styles["Normal"]
    hex_style = ParagraphStyle("hex", parent=styles["Code"], fontSize=7, leading=8.5)
    heading_style = ParagraphStyle(
        "keyheading", parent=styles["Heading2"], spaceBefore=8, spaceAfter=3
    )
    footer_style = ParagraphStyle("footer", parent=label, fontSize=8, textColor=colors.grey)

    # Labels and values in two columns so the values line up vertically.
    meta = Table(
        [
            ["Host ID:", bank.host_id],
            ["Partner ID:", user.partner_id],
            ["User ID:", user.user_id],
            ["Date:", created.isoformat()],
        ],
        colWidths=[3 * cm, 13 * cm],
        hAlign="LEFT",
    )
    meta.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 1),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )

    story = [
        Paragraph("EBICS Initialisation Letter", styles["Title"]),
        Paragraph(
            "Please verify the public-key hashes below against the keys received "
            "electronically, then sign and return this letter to your bank.",
            label,
        ),
        Spacer(1, 0.3 * cm),
        meta,
        Spacer(1, 0.2 * cm),
    ]
    for panel in panels:
        heading = f"{html.escape(panel.title)} ({html.escape(panel.version)})"
        story.append(Paragraph(heading, heading_style))
        story.append(Paragraph("<b>Exponent</b>", label))
        story.append(Paragraph(html.escape(panel.exponent), hex_style))
        story.append(Paragraph("<b>Modulus</b>", label))
        story.append(Paragraph(html.escape(panel.modulus), hex_style))
        story.append(Paragraph(f"<b>{_HASH_ALGORITHM} hash</b>", label))
        story.append(Paragraph(html.escape(panel.digest), hex_style))

    # Two signature fields side by side: a blank line to write on, with a small caption
    # of what to write beneath it. Kept together so it never splits across a page.
    signatures = Table(
        [
            ["", "", ""],
            ["Place, date", "", f"Signature ({user.user_id})"],
        ],
        colWidths=[7 * cm, 1.5 * cm, 7 * cm],
        rowHeights=[1.3 * cm, 0.5 * cm],
        hAlign="LEFT",
    )
    signatures.setStyle(
        TableStyle(
            [
                ("LINEBELOW", (0, 0), (0, 0), 0.5, colors.black),
                ("LINEBELOW", (2, 0), (2, 0), 0.5, colors.black),
                ("FONTSIZE", (0, 1), (-1, 1), 8),
                ("TEXTCOLOR", (0, 1), (-1, 1), colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 1), (-1, 1), 2),
            ]
        )
    )
    story.append(
        KeepTogether(
            [
                Spacer(1, 0.6 * cm),
                signatures,
                Spacer(1, 0.4 * cm),
                Paragraph(f"Generated with {html.escape(branding)}", footer_style),
            ]
        )
    )

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title="EBICS Initialisation Letter",
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.8 * cm,
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
  table.meta td { padding-right: 1.5em; vertical-align: top; }
  table.meta td.value { font-weight: normal; }
  table.sign { margin-top: 3em; border-collapse: collapse; }
  table.sign td.field { width: 7cm; vertical-align: bottom; }
  table.sign td.gap { width: 1.5cm; }
  .sigline { border-bottom: 1px solid #000; height: 3em; }
  .siglabel { font-size: 8pt; color: #555; padding-top: 0.3em; }
  .branding { margin-top: 2em; color: #888; font-size: 9pt; }
</style>
</head>
<body>
<h1>EBICS Initialisation Letter</h1>
<p>Please verify the public-key hashes below against the keys received electronically,
then sign and return this letter to your bank.</p>
<table class="meta">
  <tr><td><strong>Host ID</strong></td><td class="value">$host_id</td></tr>
  <tr><td><strong>Partner ID</strong></td><td class="value">$partner_id</td></tr>
  <tr><td><strong>User ID</strong></td><td class="value">$user_id</td></tr>
  <tr><td><strong>Date</strong></td><td class="value">$created</td></tr>
</table>
$panels
<table class="sign">
  <tr>
    <td class="field">
      <div class="sigline"></div><div class="siglabel">Place, date</div>
    </td>
    <td class="gap"></td>
    <td class="field">
      <div class="sigline"></div><div class="siglabel">Signature ($user_id)</div>
    </td>
  </tr>
</table>
<div class="branding">Generated with $branding</div>
</body>
</html>
"""
)
