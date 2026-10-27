"""Tests for ebicsclient.formats.hac: the customer acknowledgement (EBICS 3.0 spec 10).

The fixture is an excerpt of the HAC the ZKB test platform delivered on 2026-10-27, with the
partner ID, user ID, customer name and host ID replaced; it validates against the
pain.002.001.03 schema. The hand-written documents below cover what ZKB did not send.
"""

import datetime
import io
import zipfile
from pathlib import Path

import pytest

from ebicsclient.errors import MessageFormatError
from ebicsclient.formats import hac
from ebicsclient.models import (
    CAMT_053,
    CAMT_054_COLLECTIVE_DEBITS,
    PAIN_001,
    AcknowledgementAction,
    BusinessTransactionFormat,
)

_DATA = Path(__file__).parent / "data"
_NS = "urn:iso:std:iso:20022:tech:xsd:pain.002.001.03"


def _sample() -> bytes:
    return (_DATA / "hac_zkb_sample.xml").read_bytes()


def test_parse_reads_the_header_of_the_real_zkb_log() -> None:
    acknowledgement = hac.parse(_sample())
    assert acknowledgement.identification == "HbRZkoSsUqEBAABWAVp3lx4QrAQA"
    assert acknowledgement.created_at == datetime.datetime(
        2026, 10, 27, 20, 49, 57, 780000, tzinfo=datetime.UTC
    )
    assert acknowledgement.host_id == "EBICSHOST"
    assert len(acknowledgement.entries) == 15


def test_parse_reads_an_administrative_download() -> None:
    entry = hac.parse(_sample()).entries[0]
    assert entry.action is AcknowledgementAction.FILE_DOWNLOAD
    assert entry.reason_code == "TS01"
    assert entry.admin_order_type == "HPB"
    assert entry.service is None
    assert entry.order_id is None
    assert (entry.partner_id, entry.user_id) == ("PARTNER1", "USER1")
    assert entry.customer_name == "Test Customer"
    assert entry.timestamp == datetime.datetime(
        2026, 10, 26, 8, 6, 29, 393000, tzinfo=datetime.UTC
    )
    assert entry.additional_information == ()
    assert entry.other_identifiers == ()


def test_parse_reads_the_btf_of_each_business_order() -> None:
    # The services ZKB logged are exactly the library's BTF constants, version included
    # (ZKB sends it as MsgNameVersion).
    entries = hac.parse(_sample()).entries
    assert entries[4].service == PAIN_001
    assert entries[7].service == CAMT_053
    assert entries[7].reason_code == "TD01"  # nothing to download
    assert entries[8].service == CAMT_054_COLLECTIVE_DEBITS


def test_parse_follows_one_payment_from_upload_to_its_final_label() -> None:
    upload, verification, final = hac.parse(_sample()).entries[4:7]
    assert (upload.action, upload.reason_code) == (AcknowledgementAction.FILE_UPLOAD, "TS01")
    assert (verification.action, verification.reason_code) == (
        AcknowledgementAction.SIGNATURE_VERIFICATION,
        "DS01",
    )
    assert final.action is AcknowledgementAction.ORDER_FINAL
    assert final.reason_code is None
    assert {upload.order_id, verification.order_id, final.order_id} == {"N00O"}
    # The display of the file's first and last record, one line per AddtlInf, kept as sent.
    assert len(final.additional_information) == 20
    assert final.additional_information[1] == "    erster Satz:"


def test_parse_reads_a_rejected_signature_check() -> None:
    # The SEPA upload of 2026-10-27, which the platform accepted but never processed.
    entries = hac.parse(_sample()).entries
    assert entries[10].service == BusinessTransactionFormat(
        service_name="SCT", message_name="pain.001", message_version="09"
    )
    assert entries[10].reason_code == "TD03"


def test_parse_reads_the_suspension() -> None:
    upload, verification, refused = hac.parse(_sample()).entries[12:15]
    assert (upload.action, upload.reason_code, upload.order_id) == (
        AcknowledgementAction.SIGNATURE_UPLOAD,
        "TS01",
        "N016",
    )
    assert (verification.reason_code, verification.admin_order_type) == ("DS01", "SPR")
    assert (refused.reason_code, refused.order_id) == ("TA01", "N017")


def test_parse_accepts_a_zip_holding_one_document() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("hac.xml", _sample())
    assert len(hac.parse(buffer.getvalue()).entries) == 15


def test_parse_rejects_a_zip_holding_two_documents() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("first.xml", _sample())
        archive.writestr("second.xml", _sample())
    with pytest.raises(MessageFormatError, match=r"one pain\.002 document"):
        hac.parse(buffer.getvalue())


def test_parse_rejects_a_payment_status_report() -> None:
    # Also a pain.002, but its original message is a payment file, not "EBICS".
    with pytest.raises(MessageFormatError, match="Not a customer acknowledgement"):
        hac.parse((_DATA / "pain002_part.xml").read_bytes())


def test_parse_rejects_another_message() -> None:
    document = b'<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.053.001.08"/>'
    with pytest.raises(MessageFormatError, match=r"pain\.002"):
        hac.parse(document)


def _document(entries: str, *, original_message: str = "EBICS") -> bytes:
    return (
        f'<Document xmlns="{_NS}"><CstmrPmtStsRpt>'
        "<GrpHdr><MsgId>M1</MsgId><CreDtTm>2026-10-27T10:00:00Z</CreDtTm>"
        "<InitgPty><Id><OrgId><Othr><Id>EBICSHOST</Id></Othr></OrgId></Id></InitgPty></GrpHdr>"
        f"<OrgnlGrpInfAndSts><OrgnlMsgId>{original_message}</OrgnlMsgId>"
        f"<OrgnlMsgNmId>{original_message}</OrgnlMsgNmId></OrgnlGrpInfAndSts>"
        f"{entries}</CstmrPmtStsRpt></Document>"
    ).encode()


def _entry(action: str, identifiers: dict[str, str], *, reason: str = "") -> str:
    others = "".join(
        f"<Othr><Id>{value}</Id><SchmeNm><Prtry>{scheme}</Prtry></SchmeNm></Othr>"
        for scheme, value in identifiers.items()
    )
    return (
        f"<OrgnlPmtInfAndSts><OrgnlPmtInfId>{action}</OrgnlPmtInfId><StsRsnInf>"
        f"<Orgtr><Id><OrgId>{others}</OrgId></Id></Orgtr>{reason}</StsRsnInf>"
        "</OrgnlPmtInfAndSts>"
    )


def test_parse_reads_the_identifiers_of_an_action_on_another_order() -> None:
    # An HVE signature on another customer's order: the Ref identifiers name that order
    # (spec 10.2.3.2), and a scheme name the spec does not list is kept, not dropped.
    entry = _entry(
        "VEU_VERIFICATION",
        {
            "SystemID": "SYSTEM1",
            "AdminOrderType": "HVE",
            "OrderIDRef": "A001",
            "AdminOrderTypeRef": "BTU",
            "ServiceNameRef": "MCT",
            "ScopeRef": "CH",
            "MsgNameRef": "pain.001",
            "PartnerIDRef": "PARTNER2",
            "DataDigest": "ZGlnZXN0",
            "BankSpecific": "value",
        },
        reason="<Rsn><Cd>DS01</Cd></Rsn><AddtlInf>first</AddtlInf><AddtlInf>second</AddtlInf>",
    )
    (parsed,) = hac.parse(_document(entry)).entries
    assert parsed.action is AcknowledgementAction.DISTRIBUTED_SIGNATURE_VERIFICATION
    assert parsed.system_id == "SYSTEM1"
    assert parsed.service is None
    assert parsed.referenced_order_id == "A001"
    assert parsed.referenced_admin_order_type == "BTU"
    assert parsed.referenced_service == BusinessTransactionFormat(
        service_name="MCT", message_name="pain.001", scope="CH"
    )
    assert parsed.referenced_partner_id == "PARTNER2"
    assert parsed.data_digest == "ZGlnZXN0"
    assert parsed.additional_information == ("first", "second")
    assert parsed.other_identifiers == (("BankSpecific", "value"),)
    assert parsed.timestamp is None
    assert parsed.customer_name is None


@pytest.mark.parametrize(
    ("label", "action"),
    [
        ("ORDER_HAC_FINAL_POS", AcknowledgementAction.ORDER_FINAL_POSITIVE),
        ("ORDER_HAC_FINAL_NEG", AcknowledgementAction.ORDER_FINAL_NEGATIVE),
    ],
)
def test_parse_reads_the_final_labels_of_ebics_3_0_2(
    label: str, action: AcknowledgementAction
) -> None:
    (parsed,) = hac.parse(_document(_entry(label, {"OrderID": "A001"}))).entries
    assert parsed.action is action
    assert parsed.reason_code is None


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ("", "at least one"),
        (_entry("FILE_DELETED", {}), "Unknown type of action"),
        (
            '<OrgnlPmtInfAndSts><OrgnlPmtInfId>FILE_UPLOAD</OrgnlPmtInfId>'
            "</OrgnlPmtInfAndSts>",
            "exactly one <StsRsnInf>",
        ),
        (
            _entry("FILE_UPLOAD", {}).replace(
                "<OrgId></OrgId>", "<OrgId><Othr><Id>X</Id></Othr></OrgId>"
            ),
            "no <SchmeNm><Prtry>",
        ),
        (
            _entry("FILE_UPLOAD", {"OrderID": "A001"}).replace(
                "</OrgId>",
                "<Othr><Id>A002</Id><SchmeNm><Prtry>OrderID</Prtry></SchmeNm></Othr></OrgId>",
            ),
            "names OrderID twice",
        ),
        (
            _entry("FILE_UPLOAD", {}, reason="<Rsn><Prtry>OK</Prtry></Rsn>"),
            "ISO reason code",
        ),
        (_entry("FILE_UPLOAD", {"ServiceName": "MCT"}), "without ServiceName or MsgName"),
        (_entry("FILE_UPLOAD", {"TimeStamp": "yesterday"}), "not an ISO 8601 timestamp"),
    ],
)
def test_parse_fails_closed_on_a_malformed_log(entries: str, message: str) -> None:
    with pytest.raises(MessageFormatError, match=message):
        hac.parse(_document(entries))


def test_parse_requires_the_host_id() -> None:
    document = _document(_entry("FILE_UPLOAD", {})).replace(
        b"<InitgPty><Id><OrgId><Othr><Id>EBICSHOST</Id></Othr></OrgId></Id></InitgPty>", b""
    )
    with pytest.raises(MessageFormatError, match="InitgPty"):
        hac.parse(document)


def test_parse_rejects_malformed_xml() -> None:
    with pytest.raises(MessageFormatError, match="Malformed"):
        hac.parse(b"<Document")
