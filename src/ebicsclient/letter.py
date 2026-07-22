"""Initialisation-letter rendering (EBICS 3.0).

After INI and HIA, the subscriber sends the bank signed initialisation letters so the
bank can verify, out of band, the certificates it received electronically. EBICS 3.0
defines their content (spec section 4.4.1.2.3 and the templates in section 11.5): the
**INI letter** carries the bank-technical signature certificate (A006), the **HIA
letter** carries the identification/authentication certificate (X002) and the encryption
certificate (E002) — each as PEM, together with the **SHA-256 hash of the DER-encoded
certificate** in uppercase hexadecimal. The bank compares those hashes against the
certificates delivered over INI/HIA before activating the subscriber, so the letters must
show the *same* certificates the requests transmitted; the deterministic certificate
generation (see :func:`ebicsclient.keys.generate_self_signed_certificate`) guarantees
that for the default profile, and a caller-supplied
:class:`~ebicsclient.certificates.CertificateProvider` returns its fixed certificates.

This module renders both letters into one printable document (the INI letter first, the
HIA letter on its own page) as HTML (always available, no extra dependency) or as PDF
(the optional ``pdf`` extra, backed by reportlab).
"""

import datetime
import html
import importlib.util
import io
from dataclasses import dataclass
from string import Template

from cryptography.hazmat.primitives.serialization import Encoding

from ebicsclient.certificates import DEFAULT_CERTIFICATE_PROVIDER, CertificateProvider
from ebicsclient.errors import MissingDependencyError
from ebicsclient.keys import CertificateUsage, certificate_fingerprint
from ebicsclient.models import Bank, Keyring, Letter, OutputFormat, User

_HASH_ALGORITHM = "SHA-256"
_CONFIRMATION = "I hereby confirm the above public keys for my electronic signature."
_DEFAULT_BRANDING = "ebicsClient"


@dataclass(frozen=True, slots=True)
class _CertificatePanel:
    """The displayable facts for one certificate, pre-formatted for either output."""

    title: str
    version: str
    pem: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class _LetterSection:
    """One initialisation letter (INI or HIA), rendered as its own page."""

    order_type: str
    versions: str
    panels: tuple[_CertificatePanel, ...]


def make_ini_letter(
    bank: Bank,
    user: User,
    keyring: Keyring,
    *,
    certificate_provider: CertificateProvider = DEFAULT_CERTIFICATE_PROVIDER,
    output_format: OutputFormat = OutputFormat.AUTO,
    created: datetime.datetime | None = None,
    branding: str = _DEFAULT_BRANDING,
) -> Letter:
    """Render the EBICS 3.0 initialisation letters (INI and HIA) for a subscriber.

    The letters carry the subscriber's certificates and their SHA-256 DER fingerprints
    (EBICS 3.0 spec, sections 4.4.1.2.3 and 11.5) so the bank can verify, out of band,
    the certificates it received electronically over INI and HIA. The INI letter (the
    A006 signature certificate) and the HIA letter (the X002 authentication and E002
    encryption certificates) are rendered into one document, each on its own page —
    print, sign each page, and send them to the bank.

    Args:
        bank: The target bank (its Host ID appears on the letters).
        user: The subscriber whose certificates the letters certify.
        keyring: The subscriber's key pairs.
        certificate_provider: Supplies the certificates — it MUST be the same provider
            used for :meth:`~ebicsclient.Client.ini`/:meth:`~ebicsclient.Client.hia`, so
            the printed fingerprints match the certificates the bank received. Defaults
            to deterministic self-signed certificates (the "mit Schlüsseln" profile).
        output_format: The output format. ``AUTO`` renders PDF when the optional ``pdf``
            extra is installed, otherwise HTML.
        created: The date and time printed on the letters; defaults to now (UTC).
        branding: A name shown in the footer (e.g. the downstream product name);
            defaults to ``"ebicsClient"``.

    Returns:
        The rendered letters (their concrete format, media type, and content bytes).

    Raises:
        MissingDependencyError: PDF output was requested but the ``pdf`` extra is absent.
        TypeError: ``branding`` is not a ``str``.
        CertificateError: the provider could not supply a certificate.
    """
    if not isinstance(branding, str):
        raise TypeError(f"branding must be a str, got {type(branding).__name__}")
    resolved = _resolve_format(output_format)
    when = created if created is not None else datetime.datetime.now(datetime.UTC)
    sections = _letter_sections(user, keyring, certificate_provider)
    if resolved is OutputFormat.HTML:
        content = _render_html(bank, user, sections, when, branding)
        return Letter(
            output_format=OutputFormat.HTML, media_type="text/html; charset=utf-8", content=content
        )
    if resolved is OutputFormat.PDF:
        content = _render_pdf(bank, user, sections, when, branding)
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


def _letter_sections(
    user: User, keyring: Keyring, provider: CertificateProvider
) -> tuple[_LetterSection, ...]:
    signature = _certificate_panel(
        "Signature certificate", "A006", user, keyring, provider, CertificateUsage.SIGNATURE
    )
    authentication = _certificate_panel(
        "Authentication certificate", "X002", user, keyring, provider,
        CertificateUsage.AUTHENTICATION,
    )
    encryption = _certificate_panel(
        "Encryption certificate", "E002", user, keyring, provider, CertificateUsage.ENCRYPTION
    )
    return (
        _LetterSection(order_type="INI", versions="A006", panels=(signature,)),
        _LetterSection(
            order_type="HIA", versions="X002 and E002", panels=(authentication, encryption)
        ),
    )


def _certificate_panel(
    title: str,
    version: str,
    user: User,
    keyring: Keyring,
    provider: CertificateProvider,
    usage: CertificateUsage,
) -> _CertificatePanel:
    # Identical provider call to the INI/HIA request builders, so the certificate — and
    # therefore the printed fingerprint — matches what the bank received.
    private_key = getattr(keyring, usage.value)
    certificate = provider.certificate(usage, private_key, user.user_id)
    return _CertificatePanel(
        title=title,
        version=version,
        pem=certificate.public_bytes(Encoding.PEM).decode("ascii"),
        fingerprint=_grouped_hex_bytes(certificate_fingerprint(certificate)),
    )


def _grouped_hex_bytes(data: bytes) -> str:
    # The spec presents the hash in uppercase hexadecimal; spaced byte pairs keep it
    # readable for the person comparing it (section 11.5 formats it the same way).
    return " ".join(f"{byte:02X}" for byte in data)


def _render_html(
    bank: Bank,
    user: User,
    sections: tuple[_LetterSection, ...],
    created: datetime.datetime,
    branding: str,
) -> bytes:
    pages = "\n".join(
        _HTML_LETTER.substitute(
            order_type=html.escape(section.order_type),
            versions=html.escape(section.versions),
            host_id=html.escape(bank.host_id),
            partner_id=html.escape(user.partner_id),
            user_id=html.escape(user.user_id),
            date=html.escape(created.date().isoformat()),
            time=html.escape(created.strftime("%H:%M:%S")),
            panels="\n".join(
                _HTML_PANEL.substitute(
                    title=html.escape(panel.title),
                    version=html.escape(panel.version),
                    pem=html.escape(panel.pem),
                    fingerprint=html.escape(panel.fingerprint),
                    hash_algorithm=_HASH_ALGORITHM,
                )
                for panel in section.panels
            ),
            confirmation=html.escape(_CONFIRMATION),
        )
        for section in sections
    )
    document = _HTML_DOCUMENT.substitute(pages=pages, branding=html.escape(branding))
    return document.encode("utf-8")


def _render_pdf(
    bank: Bank,
    user: User,
    sections: tuple[_LetterSection, ...],
    created: datetime.datetime,
    branding: str,
) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            KeepTogether,
            PageBreak,
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
    pem_style = ParagraphStyle("pem", parent=styles["Code"], fontSize=6.4, leading=7.6)
    hex_style = ParagraphStyle("hex", parent=styles["Code"], fontSize=7, leading=8.5)
    heading_style = ParagraphStyle(
        "certheading", parent=styles["Heading2"], spaceBefore=8, spaceAfter=3
    )
    footer_style = ParagraphStyle("footer", parent=label, fontSize=8, textColor=colors.grey)

    story: list[object] = []
    for index, section in enumerate(sections):
        if index:
            story.append(PageBreak())
        story.append(
            Paragraph(f"EBICS Initialisation Letter ({section.order_type})", styles["Title"])
        )
        meta = Table(
            [
                ["Date:", created.date().isoformat(), "Host ID:", bank.host_id],
                ["Time:", created.strftime("%H:%M:%S"), "Partner ID:", user.partner_id],
                ["Version:", section.versions, "User ID:", user.user_id],
            ],
            colWidths=[2.4 * cm, 5.6 * cm, 2.6 * cm, 5.4 * cm],
            hAlign="LEFT",
        )
        meta.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 1),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.extend([Spacer(1, 0.3 * cm), meta, Spacer(1, 0.2 * cm)])

        for panel in section.panels:
            story.append(
                Paragraph(
                    f"{html.escape(panel.title)} — Type {html.escape(panel.version)}",
                    heading_style,
                )
            )
            pem_html = html.escape(panel.pem).replace("\n", "<br/>")
            story.append(Paragraph(pem_html, pem_style))
            story.append(
                Paragraph(
                    f"<b>Hash of the certificate ({_HASH_ALGORITHM}):</b>", label
                )
            )
            story.append(Paragraph(html.escape(panel.fingerprint), hex_style))

        signatures = Table(
            [
                ["", "", ""],
                ["Date", "", f"Signature ({user.user_id})"],
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
                    Spacer(1, 0.5 * cm),
                    Paragraph(_CONFIRMATION, label),
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
        title="EBICS Initialisation Letters",
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.8 * cm,
    )
    document.build(story)
    return buffer.getvalue()


_HTML_PANEL = Template(
    """      <section class="certificate">
        <h2>$title <span class="version">Type $version</span></h2>
        <pre class="pem">$pem</pre>
        <p class="hashlabel">Hash of the certificate ($hash_algorithm):</p>
        <p class="hex">$fingerprint</p>
      </section>"""
)

_HTML_LETTER = Template(
    """  <article class="letter">
    <h1>EBICS Initialisation Letter ($order_type)</h1>
    <table class="meta">
      <tr><td><strong>Date</strong></td><td class="value">$date</td>
          <td><strong>Host ID</strong></td><td class="value">$host_id</td></tr>
      <tr><td><strong>Time</strong></td><td class="value">$time</td>
          <td><strong>Partner ID</strong></td><td class="value">$partner_id</td></tr>
      <tr><td><strong>Version</strong></td><td class="value">$versions</td>
          <td><strong>User ID</strong></td><td class="value">$user_id</td></tr>
    </table>
$panels
    <p class="confirmation">$confirmation</p>
    <table class="sign">
      <tr>
        <td class="field">
          <div class="sigline"></div><div class="siglabel">Date</div>
        </td>
        <td class="gap"></td>
        <td class="field">
          <div class="sigline"></div><div class="siglabel">Signature ($user_id)</div>
        </td>
      </tr>
    </table>
  </article>"""
)

_HTML_DOCUMENT = Template(
    """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>EBICS Initialisation Letters</title>
<style>
  body { font-family: Helvetica, Arial, sans-serif; color: #111; margin: 2.5cm; }
  article.letter { page-break-after: always; }
  article.letter:last-child { page-break-after: auto; }
  h1 { font-size: 18pt; }
  h2 { font-size: 12pt; margin-bottom: 0.2em; }
  .version { color: #555; font-weight: normal; }
  .pem { font-family: "Courier New", monospace; font-size: 7pt; line-height: 1.25;
         background: #f7f8fa; border: 1px solid #999; padding: 0.5em;
         word-break: break-all; white-space: pre-wrap; }
  .hashlabel { font-weight: bold; margin-bottom: 0.2em; }
  .hex { font-family: "Courier New", monospace; font-size: 9pt; word-break: break-all;
         margin-top: 0; }
  .confirmation { margin-top: 1.5em; }
  table.meta td { padding-right: 1.2em; vertical-align: top; }
  table.meta td.value { font-weight: normal; }
  table.sign { margin-top: 2.5em; border-collapse: collapse; }
  table.sign td.field { width: 7cm; vertical-align: bottom; }
  table.sign td.gap { width: 1.5cm; }
  .sigline { border-bottom: 1px solid #000; height: 3em; }
  .siglabel { font-size: 8pt; color: #555; padding-top: 0.3em; }
  .branding { margin-top: 2em; color: #888; font-size: 9pt; }
</style>
</head>
<body>
$pages
<div class="branding">Generated with $branding</div>
</body>
</html>
"""
)
