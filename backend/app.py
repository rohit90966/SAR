from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
import json
import re
from typing import Any
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from jose import JWTError, jwt
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    Frame, HRFlowable, PageBreak, PageTemplate,
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

load_dotenv()

from rag_pipeline.pipeline_service import SarRagService, build_text_diff, mask_alert
from rag_pipeline.ingestion_pipeline import ingest_regulation_document
from rag_pipeline.rule_engine import load_rule_config
from .enrichment import enrich_case
from .regulation_engine import (
    check_regulatory_readiness,
    process_regulation_document,
    apply_threshold_updates,
    activate_asset_type_in_registry,
    get_registry,
)
from .database import (
    append_audit_event, create_case, get_audit_events,
    get_case, init_db, list_cases, update_case,
    quarantine_alert, release_quarantined_alerts,
    list_quarantine_queue, create_staging_entry,
    get_staging_entry, update_staging_status,
    list_staging_entries,
    record_alert_disposition,
    get_historical_fp_rate,
    record_customer_sar_approval,
    get_full_customer_kyc,
    get_customer,
    get_accounts_for_customer,
)
from .false_alert_filter import score_false_alert_probability
from .schemas import AlertPayload, ReplayResponse, ReviewRequest, RegulationUploadRequest, StagingReviewRequest

app = FastAPI(title="SAR Narrative Generator API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

service = SarRagService()

JWT_SECRET_KEY = "sar-narrative-secret"
JWT_ALGORITHM  = "HS256"
USERS = {
    "analyst": {"password": "password123", "role": "analyst"},
    "manager": {"password": "password123", "role": "manager"},
    "admin":   {"password": "password123", "role": "admin"},
}

# ── PDF sanitisation patterns ─────────────────────────────────────────────────
_PDF_ANNOTATION_RE = re.compile(
    r"\s*\((FACT|COMPARISON|REASONING|EVIDENCE|ANALYSIS|NOTE)\)\s*",
    re.IGNORECASE,
)
_PDF_BUCKET_RE = re.compile(
    r"\b(high_velocity_txns|uae_transfers|uea_transfers|structuring_txns"
    r"|evidence\s*:\s*[\w_]+)\b",
    re.IGNORECASE,
)
_PDF_EVIDENCE_MARKER_RE = re.compile(
    r"\[(?:E\d+|TXN:[^\]]+|evidence:[^\]]+)\]",
    re.IGNORECASE,
)
_ISO_TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?"
)

# Max suspicious transaction rows to show in PDF table
# Keeps PDF readable — shows first N rows then a summary line
PDF_TXN_TABLE_MAX_ROWS = 20


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def serialise(payload: Any) -> Any:
    return jsonable_encoder(payload)


def build_case_response(case_record: dict[str, Any]) -> dict[str, Any]:
    response = serialise(case_record)
    response["audit_events"] = serialise(get_audit_events(str(case_record["case_id"])))
    return response


class LoginRequest(BaseModel):
    username: str
    password: str


def get_current_user(authorization: str = Header(default="")) -> dict[str, str]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization.replace("Bearer ", "", 1)
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    username = payload.get("username")
    role     = payload.get("role")
    if not username or not role:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    return {"username": username, "role": role}


# ════════════════════════════════════════════════════════
# PDF SANITISATION
# ════════════════════════════════════════════════════════

def _sanitise_for_pdf(text: str, alert_payload: dict[str, Any]) -> str:
    """
    Defence-in-depth sanitisation before any narrative text enters the PDF.
    Strips annotation tags, enrichment bucket names, evidence markers,
    raw customer identifiers, and raw ISO timestamps.
    """
    if not text:
        return text

    text = _PDF_ANNOTATION_RE.sub(" ", text)
    text = _PDF_BUCKET_RE.sub("", text)
    text = _PDF_EVIDENCE_MARKER_RE.sub("", text)

    customer_name = str(alert_payload.get("customer_name") or "")
    customer_id   = str(alert_payload.get("customer_id") or "")
    if customer_name and customer_name != "N/A":
        text = re.sub(re.escape(customer_name), "the account holder", text, flags=re.IGNORECASE)
    if customer_id and customer_id != "N/A":
        text = re.sub(re.escape(customer_id), "", text, flags=re.IGNORECASE)

    if text.strip().startswith("{"):
        try:
            obj = json.loads(text.strip())
            for key in ("sentence", "text", "content", "narrative"):
                if key in obj and isinstance(obj[key], str):
                    text = obj[key]
                    break
        except (json.JSONDecodeError, ValueError):
            pass

    def _fmt_ts(m: re.Match) -> str:
        try:
            dt = datetime.fromisoformat(m.group(0).replace("Z", "+00:00"))
            return dt.strftime("%d %b %Y %H:%M UTC")
        except ValueError:
            return m.group(0)

    text = _ISO_TIMESTAMP_RE.sub(_fmt_ts, text)
    text = re.sub(r"  +", " ", text).strip()
    return text


def enrich_narrative_with_pii(narrative: str, alert_payload: dict[str, Any]) -> str:
    """
    Re-inserts customer name at PDF export time ONLY.
    The narrative was processed with 'the account holder' throughout.
    """
    customer_name    = str(alert_payload.get("customer_name") or "N/A")
    account_type     = str(alert_payload.get("account_type") or "N/A")

    # BUG WARN #5 FIX: removed r"\ba\s+student\b" replacement
    # customer_profile != occupation — do not conflate them
    replacements = [
        (r"\ba\s+savings\s+account\b", f"{account_type} account"),
    ]

    enriched = narrative or ""
    for pattern, replacement in replacements:
        enriched = re.sub(pattern, replacement, enriched, flags=re.IGNORECASE)
    return enriched


def _extract_narrative_sections(
    final_sar: dict[str, Any],
    alert_payload: dict[str, Any],
) -> list[tuple[str, str]]:
    """Extract (section_title, enriched_prose) tuples for PDF rendering."""
    narrative = final_sar.get("narrative", "")
    default_titles = ["Background", "Transaction Summary", "Typology", "Evidence", "Conclusion"]

    if isinstance(narrative, dict):
        sections: list[tuple[str, str]] = []
        for key, value in narrative.items():
            raw      = _safe_value(value)
            clean    = _sanitise_for_pdf(raw, alert_payload)
            enriched = enrich_narrative_with_pii(clean, alert_payload)
            sections.append((_safe_value(key), enriched))
        return sections

    narrative_str = str(narrative)
    paragraphs: list[str] = []

    by_blank = [p.strip() for p in narrative_str.split("\n\n") if p.strip()]
    if len(by_blank) == 5:
        paragraphs = by_blank
    else:
        numbered_split = re.split(r"\n(?=\d+[\.\)]\s)", narrative_str.strip())
        by_number = [
            re.sub(r"^\d+[\.\)]\s*", "", p).strip()
            for p in numbered_split if p.strip()
        ]
        paragraphs = by_blank if len(by_blank) >= len(by_number) else by_number

    while len(paragraphs) < 5:
        paragraphs.append("N/A")

    result: list[tuple[str, str]] = []
    for idx, title in enumerate(default_titles):
        raw      = paragraphs[idx] if idx < len(paragraphs) else "N/A"
        clean    = _sanitise_for_pdf(raw, alert_payload)
        enriched = enrich_narrative_with_pii(clean, alert_payload)
        result.append((title, enriched))
    return result


# ════════════════════════════════════════════════════════
# PDF HELPERS
# ════════════════════════════════════════════════════════

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        page_count = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_page_number(page_count)
            super().showPage()
        super().save()

    def _draw_page_number(self, page_count: int) -> None:
        self.saveState()
        self.setFillColor(colors.HexColor("#6C757D"))
        self.setFont("Helvetica", 8)
        self.drawRightString(
            A4[0] - (2 * cm), 1.1 * cm,
            f"Page {self._pageNumber} of {page_count}",
        )
        self.restoreState()


def _safe_value(value: Any) -> str:
    if value is None:
        return "N/A"
    text = str(value).strip()
    return text if text else "N/A"


def _section_bar(title: str, doc_width: float) -> Table:
    bar = Table([[title]], colWidths=[doc_width])
    bar.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#003366")),
        ("TEXTCOLOR",     (0, 0), (-1, -1), colors.white),
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 10),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return bar


def _risk_color(risk_level: str) -> colors.Color:
    level = (risk_level or "N/A").upper()
    if level == "HIGH":   return colors.HexColor("#DC3545")
    if level == "MEDIUM": return colors.HexColor("#FD7E14")
    if level == "LOW":    return colors.HexColor("#28A745")
    return colors.black


def _make_footer(decision: str):
    dec = (decision or "PENDING").upper()
    if dec == "APPROVE":
        label = "Reviewed and APPROVED by qualified compliance analyst"
    elif dec in ("REJECT", "REJECTED"):
        label = "Reviewed and REJECTED by qualified compliance analyst"
    else:
        label = "Pending analyst review"

    def _draw_footer(canvas_obj: canvas.Canvas, _: Any) -> None:
        canvas_obj.saveState()
        footer_gray = colors.HexColor("#6C757D")
        y_line = 1.7 * cm
        canvas_obj.setStrokeColor(footer_gray)
        canvas_obj.setLineWidth(0.5)
        canvas_obj.line(2 * cm, y_line, A4[0] - (2 * cm), y_line)
        canvas_obj.setFillColor(footer_gray)
        canvas_obj.setFont("Helvetica", 8)
        canvas_obj.drawString(2 * cm, 1.15 * cm, "CONFIDENTIAL - NOT FOR DISTRIBUTION")
        canvas_obj.drawCentredString(
            A4[0] / 2, 1.15 * cm,
            f"SAR Narrative Generator - Barclays Hack-O-Hire 2026 | {label}",
        )
        canvas_obj.restoreState()
    return _draw_footer


def _build_txn_table(
    txn_rows: list[dict[str, Any]],
    doc_width: float,
    normal_9: ParagraphStyle,
    bold_9: ParagraphStyle,
    italic_8_gray: ParagraphStyle,
) -> list[Any]:
    """
    Builds the Suspicious Transactions table flowables for the PDF.

    Shows up to PDF_TXN_TABLE_MAX_ROWS individual transactions.
    If there are more, appends a summary row indicating the remainder.

    Columns: TXN ID | Date | Amount (INR) | Type | Country | Counterparty
    """
    flow: list[Any] = []

    if not txn_rows:
        flow.append(Paragraph("No transaction records available from enrichment.", italic_8_gray))
        return flow

    col_widths = [75, 65, 85, 45, 55, doc_width - 75 - 65 - 85 - 45 - 55]

    header_row = [
        Paragraph("TXN ID",       bold_9),
        Paragraph("Date",         bold_9),
        Paragraph("Amount (INR)", bold_9),
        Paragraph("Type",         bold_9),
        Paragraph("Country",      bold_9),
        Paragraph("Counterparty", bold_9),
    ]

    visible_rows = txn_rows[:PDF_TXN_TABLE_MAX_ROWS]
    remaining    = len(txn_rows) - len(visible_rows)

    table_data: list[list[Any]] = [header_row]

    for row in visible_rows:
        amount_fmt = f"{float(row['amount']):,.2f}"
        txn_type   = str(row.get("txn_type", "")).upper()
        type_color = "#DC3545" if txn_type == "DEBIT" else "#28A745"

        table_data.append([
            Paragraph(str(row.get("txn_id", "N/A")), normal_9),
            Paragraph(str(row.get("date",   "N/A")), normal_9),
            Paragraph(amount_fmt,                     normal_9),
            Paragraph(
                f"<font color='{type_color}'><b>{txn_type}</b></font>",
                normal_9,
            ),
            Paragraph(str(row.get("country",      "N/A")), normal_9),
            Paragraph(str(row.get("counterparty", "N/A")), normal_9),
        ])

    if remaining > 0:
        table_data.append([
            Paragraph(
                f"<i>... and {remaining} additional transactions not shown. "
                f"Full record available in case audit trail.</i>",
                italic_8_gray,
            ),
            "", "", "", "", "",
        ])

    txn_table = Table(table_data, colWidths=col_widths)

    style = [
        ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
        ("BACKGROUND",    (0, 0), (-1,  0), colors.HexColor("#DDE7F0")),
        ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#C7CED6")),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 3),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 3),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for i in range(1, len(table_data)):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#F5F5F5")))

    if remaining > 0:
        last_row = len(table_data) - 1
        style.append(("SPAN",       (0, last_row), (-1, last_row)))
        style.append(("BACKGROUND", (0, last_row), (-1, last_row), colors.HexColor("#FFF8E1")))

    txn_table.setStyle(TableStyle(style))
    flow.append(txn_table)

    # Totals row
    if txn_rows:
        total_amount = sum(float(r["amount"]) for r in txn_rows)
        debit_count  = sum(1 for r in txn_rows if r.get("txn_type") == "debit")
        credit_count = sum(1 for r in txn_rows if r.get("txn_type") == "credit")
        flow.append(Spacer(1, 4))
        flow.append(Paragraph(
            f"<b>Total transactions:</b> {len(txn_rows)} &nbsp;&nbsp; "
            f"<b>Credits:</b> {credit_count} &nbsp;&nbsp; "
            f"<b>Debits:</b> {debit_count} &nbsp;&nbsp; "
            f"<b>Aggregate Amount:</b> INR {total_amount:,.2f}",
            normal_9,
        ))

    return flow


# ════════════════════════════════════════════════════════
# MAIN PDF BUILDER
# ════════════════════════════════════════════════════════

def _build_pdf(case_record: dict[str, Any]) -> bytes:
    final_sar          = case_record.get("final_sar") or {}
    alert_payload      = case_record.get("alert_payload") or {}
    evidence_pack      = case_record.get("evidence_pack") or {}
    analyst_review     = case_record.get("analyst_review") or {}
    prompt_payload     = case_record.get("prompt_payload") or {}
    retrieval_payload  = case_record.get("retrieval_payload") or {}
    enrichment_payload = case_record.get("enrichment_payload") or {}

    # PII-sealed enrichment data (transaction rows, account dates, etc.)
    pii_sealed = enrichment_payload.get("pii_sealed") or {}

    # Fetch canonical customer fields from DB as a final fallback.
    customer_id_raw = alert_payload.get("customer_id") or final_sar.get("customer_id")
    kyc_record: dict[str, Any] = {}
    basic_customer: dict[str, Any] = {}
    customer_accounts: list[dict[str, Any]] = []
    if customer_id_raw:
        try:
            kyc_record = get_full_customer_kyc(str(customer_id_raw)) or {}
        except Exception:
            kyc_record = {}
        try:
            basic_customer = get_customer(str(customer_id_raw)) or {}
        except Exception:
            basic_customer = {}
        try:
            customer_accounts = get_accounts_for_customer(str(customer_id_raw)) or []
        except Exception:
            customer_accounts = []

    db_account_types = kyc_record.get("account_types") or []
    db_primary_account_type = (
        str(db_account_types[0])
        if db_account_types
        else (str(customer_accounts[0].get("account_type")) if customer_accounts else None)
    )

    db_earliest_account = kyc_record.get("earliest_account_date")
    if not db_earliest_account and customer_accounts:
        opened_dates = [a.get("opened_date") for a in customer_accounts if a.get("opened_date")]
        if opened_dates:
            try:
                db_earliest_account = min(opened_dates)
            except Exception:
                db_earliest_account = opened_dates[0]
    if db_earliest_account:
        try:
            account_opened_date_db = db_earliest_account.strftime("%d %b %Y")
        except Exception:
            account_opened_date_db = str(db_earliest_account)
    else:
        account_opened_date_db = None

    # PII fields from alert_payload — reinserted at export time
    customer_name    = _safe_value(
        alert_payload.get("customer_name")
        or pii_sealed.get("customer_name")
        or kyc_record.get("name")
        or basic_customer.get("name")
    )
    customer_id      = _safe_value(customer_id_raw)
    account_type     = _safe_value(
        alert_payload.get("account_type") or db_primary_account_type
    )
    alert_id         = _safe_value(alert_payload.get("alert_id") or case_record.get("alert_id"))
    alert_type       = _safe_value(alert_payload.get("alert_type") or final_sar.get("alert_type"))
    customer_profile = _safe_value(
        alert_payload.get("customer_profile")
        or pii_sealed.get("occupation")
        or kyc_record.get("occupation")
        or basic_customer.get("occupation")
    )

    transactions        = alert_payload.get("transactions") or {}
    txn_details = evidence_pack.get("transaction_details") or {}
    total_amount        = _safe_value(transactions.get("total_amount"))
    transaction_count   = _safe_value(transactions.get("transaction_count"))
    time_window_days    = _safe_value(transactions.get("time_window_days"))
    destination_country = _safe_value(transactions.get("destination_country"))

    if total_amount == "N/A":
        total_amount = _safe_value(txn_details.get("total_amount"))
    if transaction_count == "N/A":
        transaction_count = _safe_value(txn_details.get("transaction_count"))
    if time_window_days == "N/A":
        time_window_days = _safe_value(txn_details.get("time_window_days"))
    if destination_country == "N/A":
        destination_country = _safe_value(txn_details.get("destination_country"))

    risk_level = _safe_value(case_record.get("risk_level") or final_sar.get("risk_level"))
    risk_score = case_record.get("risk_score")
    try:
        risk_score_pct = f"{round(float(risk_score) * 100)}%"
    except Exception:
        risk_score_pct = "N/A"

    generated_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    txn_table_rows  = pii_sealed.get("txn_table_rows") or []
    alert_window_start_fmt = (
        pii_sealed.get("alert_window_start_fmt")
        or _safe_value(alert_payload.get("alert_window_start"))
    )
    alert_window_end_fmt = (
        pii_sealed.get("alert_window_end_fmt")
        or _safe_value(alert_payload.get("alert_window_end"))
    )
    occupation             = (
        pii_sealed.get("occupation")
        or kyc_record.get("occupation")
        or basic_customer.get("occupation")
        or "N/A"
    )
    risk_rating_kyc        = (
        pii_sealed.get("risk_rating")
        or kyc_record.get("risk_rating")
        or basic_customer.get("risk_rating")
        or "N/A"
    )
    account_opened_date    = pii_sealed.get("account_opened_date") or account_opened_date_db or "N/A"

    # Safe stats for display
    safe_stats = enrichment_payload.get("safe_stats") or {}
    unique_counterparties  = safe_stats.get("unique_counterparties_count") or "N/A"
    new_counterparties     = safe_stats.get("new_counterparties_count") or "N/A"
    has_prior_relationship = safe_stats.get("has_prior_relationship")

    # Style setup
    styles        = getSampleStyleSheet()
    body_style    = ParagraphStyle("Body",     parent=styles["BodyText"],  fontName="Helvetica",        fontSize=10, leading=14)
    normal_9      = ParagraphStyle("Normal9",  parent=styles["Normal"],    fontName="Helvetica",        fontSize=9,  leading=12)
    bold_9        = ParagraphStyle("Bold9",    parent=normal_9,            fontName="Helvetica-Bold")
    italic_8_gray = ParagraphStyle("Italic8",  parent=styles["Italic"],    fontName="Helvetica-Oblique",fontSize=8,  textColor=colors.HexColor("#6C757D"))
    small_mono    = ParagraphStyle("Mono8",    parent=normal_9,            fontName="Courier",          fontSize=8,  leading=10)

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm,  bottomMargin=2*cm,
    )
    decision = _safe_value((case_record.get("analyst_review") or {}).get("decision") or "PENDING")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="content")
    doc.addPageTemplates([PageTemplate(id="with-footer", frames=[frame], onPage=_make_footer(decision))])

    flow: list[Any] = []
    W = doc.width  # shorthand for doc width

    # ── PAGE 1: HEADER ───────────────────────────────────────────────────
    header = Table(
        [[
            Paragraph("SUSPICIOUS ACTIVITY REPORT",
                      ParagraphStyle("HdrTitle", fontName="Helvetica-Bold", fontSize=16, textColor=colors.white)),
            Paragraph("CONFIDENTIAL",
                      ParagraphStyle("HdrConf", fontName="Helvetica-Bold", fontSize=11,
                                     textColor=colors.HexColor("#DC3545"), alignment=2)),
        ]],
        colWidths=[W * 0.75, W * 0.25],
    )
    header.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#003366")),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    flow.append(header)
    flow.append(Spacer(1, 8))

    risk_color_text = "#28A745"
    if risk_level.upper() == "HIGH":   risk_color_text = "#DC3545"
    elif risk_level.upper() == "MEDIUM": risk_color_text = "#FD7E14"

    meta_left  = Paragraph(
        f"<b>Case ID:</b> {_safe_value(case_record.get('case_id'))}<br/>"
        f"<b>Alert ID:</b> {alert_id}",
        normal_9,
    )
    meta_right = Paragraph(
        f"<b>Generated:</b> {generated_date}<br/>"
        f"<b>Risk Level:</b> <font color='{risk_color_text}'>{risk_level}</font>",
        normal_9,
    )
    meta_table = Table([[meta_left, meta_right]], colWidths=[W*0.5, W*0.5])
    meta_table.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    flow.append(meta_table)
    flow.append(Spacer(1, 6))
    flow.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#003366")))
    flow.append(Spacer(1, 12))

    # ── PII NOTICE ───────────────────────────────────────────────────────
    flow.append(_section_bar("Identity Verification Notice", W))
    pii_body = Paragraph(
        "<b>Identity Verification Notice</b><br/>"
        "PII fields were excluded from AI processing to prevent model exposure. "
        "Personal details have been reinserted at export time from the original "
        "verified alert record and KYC database only.",
        normal_9,
    )
    pii_data = [
        [Paragraph("Customer Name", bold_9), Paragraph("Customer ID", bold_9),
         Paragraph("Account Type", bold_9),  Paragraph("Occupation", bold_9)],
        [Paragraph(customer_name, normal_9), Paragraph(customer_id, normal_9),
         Paragraph(account_type, normal_9),  Paragraph(occupation, normal_9)],
    ]
    pii_inner = Table(pii_data, colWidths=[W/4]*4)
    pii_inner.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, colors.HexColor("#D4AF37")),
        ("LINEAFTER", (0, 0), (2, -1), 0.5, colors.HexColor("#D4AF37")),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    pii_outer = Table([[[pii_body, Spacer(1, 6), pii_inner]]], colWidths=[W])
    pii_outer.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#FFFBE6")),
        ("BOX",           (0, 0), (-1, -1), 0.5, colors.HexColor("#E6C800")),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    flow.append(pii_outer)
    flow.append(Spacer(1, 12))

    # ── SUBJECT & ACTIVITY SUMMARY ───────────────────────────────────────
    flow.append(_section_bar("Subject & Activity Summary", W))
    left_summary = (
        f"<b>Alert Type:</b> {alert_type}<br/>"
        f"<b>Customer Profile:</b> {customer_profile}<br/>"
        f"<b>Account Type:</b> {account_type}<br/>"
        f"<b>KYC Risk Rating:</b> {risk_rating_kyc}<br/>"
        f"<b>Account Opened:</b> {account_opened_date}"
    )
    right_summary = (
        f"<b>Total Amount:</b> INR {total_amount}<br/>"
        f"<b>Transaction Count:</b> {transaction_count}<br/>"
        f"<b>Time Window:</b> {time_window_days} days<br/>"
        f"<b>Alert Window:</b> {alert_window_start_fmt} – {alert_window_end_fmt}<br/>"
        f"<b>Destination:</b> {destination_country}"
    )
    summary_table = Table(
        [[Paragraph(left_summary, normal_9), Paragraph(right_summary, normal_9)]],
        colWidths=[W/2, W/2],
    )
    summary_table.setStyle(TableStyle([
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    flow.append(summary_table)
    flow.append(Spacer(1, 12))

    # ── COUNTERPARTY INTELLIGENCE ────────────────────────────────────────
    flow.append(_section_bar("Counterparty Intelligence", W))
    prior_rel_text = "Yes — prior relationship identified" if has_prior_relationship else "No — all counterparties new to this customer"
    counterparty_info = (
        f"<b>Unique Counterparties in Alert Window:</b> {unique_counterparties}&nbsp;&nbsp;&nbsp;"
        f"<b>New Counterparties (never seen in 12m history):</b> {new_counterparties}&nbsp;&nbsp;&nbsp;"
        f"<b>Prior Relationship:</b> {prior_rel_text}"
    )
    flow.append(Paragraph(counterparty_info, normal_9))
    flow.append(Spacer(1, 12))

    # ── TRIGGERED AML RULES TABLE ────────────────────────────────────────
    flow.append(_section_bar("Triggered AML Rules", W))
    rules = evidence_pack.get("rule_summary") or []
    rules_data: list[list[Any]] = [
        [Paragraph("Rule ID", bold_9), Paragraph("Rule Name", bold_9),
         Paragraph("Confidence", bold_9), Paragraph("Regulation", bold_9)]
    ]
    for rule in rules:
        cv = rule.get("confidence")
        try:
            cpct = f"{round(float(cv) * 100)}%"
        except Exception:
            cpct = "N/A"
        rules_data.append([
            Paragraph(_safe_value(rule.get("rule_id")),   normal_9),
            Paragraph(_safe_value(rule.get("rule_name")), normal_9),
            Paragraph(cpct,                                normal_9),
            Paragraph(_safe_value(rule.get("regulation")), normal_9),
        ])
    rules_data.append([
        Paragraph("<b>Aggregate Risk Score</b>", normal_9),
        Paragraph("", normal_9),
        Paragraph(f"<b>{risk_score_pct}</b>", normal_9),
        Paragraph(f"<font color='{risk_color_text}'><b>{risk_level}</b></font>", normal_9),
    ])

    rules_table = Table(rules_data, colWidths=[60, 180, 70, W - 60 - 180 - 70])
    rule_style = [
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DDE7F0")),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#C7CED6")),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 3),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 3),
    ]
    for i in range(1, max(len(rules_data) - 1, 1)):
        if i % 2 == 0:
            rule_style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#F5F5F5")))
    agg = len(rules_data) - 1
    rule_style.extend([
        ("FONTNAME",    (0, agg), (-1, agg), "Helvetica-Bold"),
        ("BACKGROUND",  (2, agg), (3, agg), _risk_color(risk_level)),
        ("TEXTCOLOR",   (2, agg), (3, agg),
         colors.white if risk_level.upper() != "MEDIUM" else colors.HexColor("#1F2937")),
    ])
    rules_table.setStyle(TableStyle(rule_style))
    flow.append(rules_table)

    # ── PAGE BREAK — Narrative starts on new page ────────────────────────
    flow.append(PageBreak())

    flow.append(Paragraph(
        "Note: Narrative below contains reinserted identity fields not processed by the AI model.",
        italic_8_gray,
    ))
    flow.append(Spacer(1, 12))

    # ── NARRATIVE SECTIONS ───────────────────────────────────────────────
    for title, section_text in _extract_narrative_sections(final_sar, alert_payload):
        flow.append(_section_bar(title, W))
        flow.append(Paragraph(_safe_value(section_text), body_style))
        flow.append(Spacer(1, 12))

    # ── SUSPICIOUS TRANSACTIONS TABLE ────────────────────────────────────
    # This table is populated from enrichment pii_sealed data.
    # It contains the actual DB transaction records from the alert window.
    # This satisfies the FinCEN requirement to include specific transaction details.
    flow.append(PageBreak())
    flow.append(_section_bar("Suspicious Transactions — Alert Window Detail", W))
    flow.append(Spacer(1, 6))

    if txn_table_rows:
        flow.append(Paragraph(
            f"The following {len(txn_table_rows)} transactions were identified during the "
            f"alert window ({alert_window_start_fmt} – {alert_window_end_fmt}). "
            "These records are sourced directly from the institution's transaction database "
            "and were not processed by the AI model.",
            normal_9,
        ))
        flow.append(Spacer(1, 6))
        flow.extend(_build_txn_table(txn_table_rows, W, normal_9, bold_9, italic_8_gray))
    else:
        flow.append(Paragraph(
            "Transaction detail records were not available from the enrichment layer. "
            "Refer to the institution's transaction monitoring system for individual records.",
            italic_8_gray,
        ))
    flow.append(Spacer(1, 12))

    # ── ANALYST REVIEW ───────────────────────────────────────────────────
    flow.append(_section_bar("Analyst Review", W))
    decision = _safe_value(analyst_review.get("decision") or "PENDING")
    if decision.upper() == "APPROVE":
        decision_label, decision_color = "APPROVED",      colors.HexColor("#28A745")
    elif decision.upper() == "REJECT":
        decision_label, decision_color = "REJECTED",      colors.HexColor("#DC3545")
    else:
        decision_label, decision_color = "PENDING REVIEW",colors.HexColor("#6C757D")

    decision_box = Table([[decision_label]], colWidths=[W])
    decision_box.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), decision_color),
        ("TEXTCOLOR",     (0, 0), (-1, -1), colors.white),
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 10),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    flow.append(decision_box)
    flow.append(Spacer(1, 6))

    if analyst_review:
        flow.append(Paragraph(f"<b>Comment:</b>     {_safe_value(analyst_review.get('comment'))}", normal_9))
        flow.append(Paragraph(f"<b>Reviewed by:</b> {_safe_value(analyst_review.get('analyst_id'))}", normal_9))
        flow.append(Paragraph(f"<b>Timestamp:</b>   {_safe_value(analyst_review.get('submitted_at'))}", normal_9))
    else:
        flow.append(Paragraph("Awaiting analyst review.", italic_8_gray))
    flow.append(Spacer(1, 12))

    # ── AUDIT REFERENCE ───────────────────────────────────────────────────
    flow.append(_section_bar("Audit & Reproducibility Reference", W))
    prompt_sha256      = _safe_value(prompt_payload.get("prompt_sha256") or prompt_payload.get("prompt_sha"))
    corpus_snapshot    = retrieval_payload.get("corpus_snapshot") if isinstance(retrieval_payload, dict) else {}
    corpus_snapshot_id = _safe_value((corpus_snapshot or {}).get("snapshot_id"))
    model_name         = _safe_value(prompt_payload.get("model_name"))
    temperature        = _safe_value((prompt_payload.get("model_options") or {}).get("temperature"))
    pipeline_version   = _safe_value(
        case_record.get("pipeline_version")
        or prompt_payload.get("pipeline_version")
        or "2.0.0"
    )
    enriched_flag = "Yes" if enrichment_payload.get("enriched") else "No (alert payload used)"

    audit_rows = [
        [Paragraph("Prompt SHA256:",    bold_9), Paragraph(prompt_sha256,      small_mono)],
        [Paragraph("Corpus Snapshot:",  bold_9), Paragraph(corpus_snapshot_id, normal_9)],
        [Paragraph("Model:",            bold_9), Paragraph(model_name,         normal_9)],
        [Paragraph("Temperature:",      bold_9), Paragraph(temperature,        normal_9)],
        [Paragraph("Pipeline Version:", bold_9), Paragraph(pipeline_version,   normal_9)],
        [Paragraph("DB Enrichment:",    bold_9), Paragraph(enriched_flag,      normal_9)],
    ]
    audit_table = Table(audit_rows, colWidths=[W * 0.28, W * 0.72])
    audit_table.setStyle(TableStyle([
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D7DE")),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
    ]))
    flow.append(audit_table)
    flow.append(Spacer(1, 8))
    flow.append(Paragraph(
        "This report was generated by an AI-assisted pipeline. "
        "The narrative was reviewed and approved by a qualified compliance analyst. "
        "Customer financial data was fetched from the institution's KYC database at case creation time. "
        "The full immutable audit trail is available by referencing the Case ID above.",
        italic_8_gray,
    ))

    doc.build(flow, canvasmaker=NumberedCanvas)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


# ════════════════════════════════════════════════════════
# API ROUTES
# ════════════════════════════════════════════════════════

@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "sar-narrative-generator",
        "timestamp": utc_now(),
    }


@app.post("/login")
def login(request: LoginRequest) -> dict[str, Any]:
    user = USERS.get(request.username)
    if not user or user["password"] != request.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    payload = {
        "username": request.username,
        "role":     user["role"],
        "iat":      int(datetime.now(timezone.utc).timestamp()),
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return {
        "access_token": token,
        "token_type":   "bearer",
        "username":     request.username,
        "role":         user["role"],
    }


@app.get("/cases")
def get_cases(_: dict[str, str] = Depends(get_current_user)) -> list[dict[str, Any]]:
    return serialise(list_cases())


@app.post("/cases")
def create_new_case(
    alert: AlertPayload,
    _: dict[str, str] = Depends(get_current_user),
) -> dict[str, Any]:
    alert_payload = serialise(alert)
    asset_type = alert_payload.get("asset_type", "FIAT_WIRE")

    # ── REGULATORY PRE-FLIGHT CHECK ──────────────────────────────────────
    readiness = check_regulatory_readiness(asset_type)

    if not readiness["ready"]:
        quarantine_id = str(uuid4())
        quarantine_alert(
            quarantine_id=quarantine_id,
            alert_payload=alert_payload,
            asset_type=asset_type,
            reason=readiness["message"],
            missing_items=readiness["missing"],
        )
        return JSONResponse(
            status_code=202,
            content={
                "status": "QUARANTINED",
                "quarantine_id": quarantine_id,
                "asset_type": asset_type,
                "regulatory_status": readiness["status"],
                "missing": readiness["missing"],
                "message": readiness["message"],
                "action_required": (
                    f"Upload the governing regulation document via "
                    f"POST /regulations/upload with asset_type='{asset_type}'. "
                    f"Once activated, this alert will be automatically reprocessed."
                ),
                "alert_id": alert_payload.get("alert_id"),
                "quarantined_at": utc_now(),
            },
        )

    # Regulatory framework confirmed active — proceed
    case_id = str(uuid4())
    masked_alert_payload = mask_alert(alert_payload)
    create_case(case_id, alert_payload, masked_alert_payload)

    # ── FALSE ALERT FILTER ────────────────────────────────────────────────
    # Run the rule engine early to get evidence_blocks for scoring.
    # We need these BEFORE enrichment so we can decide whether to
    # run enrichment at all. The rule engine is cheap - it reads from
    # the already-cached rules.yaml and does pure in-memory math.
    # Note: service.process_alert() will call evaluate_rules() again
    # internally - that is intentional. The second call uses the
    # enriched alert_payload with customer_financials added, which
    # may cause additional rules to fire. The pre-filter call here
    # uses the raw alert_payload only for verdict scoring.
    from rag_pipeline.rule_engine import evaluate_rules as _evaluate_rules_early
    early_evidence_blocks = _evaluate_rules_early(alert_payload)

    fp_result = score_false_alert_probability(alert_payload, early_evidence_blocks)
    update_case(case_id, false_alert_score=fp_result)

    append_audit_event(case_id, "FALSE_ALERT_SCORED", {
        "verdict": fp_result["verdict"],
        "true_positive_score": fp_result["true_positive_score"],
        "signals": fp_result["signals"],
        "rule_ids_evaluated": fp_result["rule_ids_evaluated"],
        "threshold_rules_fired": fp_result["threshold_rules_fired"],
        "keyword_rules_fired": fp_result["keyword_rules_fired"],
        "recommendation": fp_result["recommendation"],
    })

    if fp_result["verdict"] == "LIKELY_FALSE":
        # Auto-close - stop here, nothing expensive runs.
        record_alert_disposition(
            case_id=case_id,
            rule_ids=fp_result["rule_ids_evaluated"],
            customer_profile=fp_result.get("customer_profile_used") or alert_payload.get("customer_profile", ""),
            disposition="FALSE_POSITIVE",
            disposed_by="AUTO_FILTER",
        )
        update_case(case_id, status="AUTO_CLOSED_FALSE_POSITIVE")
        return JSONResponse(
            status_code=200,
            content={
                "status": "AUTO_CLOSED_FALSE_POSITIVE",
                "case_id": case_id,
                "alert_id": alert_payload.get("alert_id"),
                "verdict": fp_result["verdict"],
                "true_positive_score": fp_result["true_positive_score"],
                "signals": fp_result["signals"],
                "rule_ids_evaluated": fp_result["rule_ids_evaluated"],
                "recommendation": fp_result["recommendation"],
                "message": (
                    "Alert scored as likely false positive and auto-closed. "
                    "No enrichment, LLM generation, or ChromaDB retrieval was performed. "
                    "Disposition recorded for feedback loop improvement."
                ),
            },
        )

    elif fp_result["verdict"] == "BORDERLINE":
        # Send to triage - analyst reviews rule summary, no LLM runs.
        update_case(case_id, status="PENDING_TRIAGE")
        append_audit_event(case_id, "SENT_TO_TRIAGE", {
            "reason": "False alert score in borderline range",
            "score": fp_result["true_positive_score"],
            "signals": fp_result["signals"],
        })
        return JSONResponse(
            status_code=202,
            content={
                "status": "PENDING_TRIAGE",
                "case_id": case_id,
                "alert_id": alert_payload.get("alert_id"),
                "verdict": fp_result["verdict"],
                "true_positive_score": fp_result["true_positive_score"],
                "signals": fp_result["signals"],
                "rule_summary": [
                    {
                        "rule_id": b["rule_id"],
                        "rule_name": b["rule_name"],
                        "confidence": b["confidence"],
                        "observation": b["observation"],
                        "why_flagged": b["audit_reason"]["why_flagged"],
                    }
                    for b in early_evidence_blocks
                ],
                "recommendation": fp_result["recommendation"],
                "message": (
                    "Alert sent to analyst triage queue. "
                    "No LLM narrative was generated. "
                    "Analyst can escalate to full pipeline or close as false positive."
                ),
            },
        )

    # LIKELY_TRUE - fall through to full pipeline below.
    # ── END FALSE ALERT FILTER ────────────────────────────────────────────

    # ── Enrichment ───────────────────────────────────────────────────────
    enrichment_result = enrich_case(alert_payload)

    if enrichment_result.get("enriched"):
        safe_stats = enrichment_result["safe_stats"]
        alert_payload["customer_financials"] = {
            "declared_monthly_income":       safe_stats.get("declared_monthly_income"),
            "avg_monthly_deposits_12m":      safe_stats.get("avg_monthly_deposits_12m"),
            "historical_baseline_txn_count": safe_stats.get("historical_baseline_txn_count"),
            "deviation_from_baseline_pct":   safe_stats.get("deviation_from_baseline_pct"),
        }
        alert_payload["_enrichment_context"] = {
            "unique_counterparties_count": safe_stats.get("unique_counterparties_count"),
            "new_counterparties_count":    safe_stats.get("new_counterparties_count"),
            "has_prior_relationship":      safe_stats.get("has_prior_relationship"),
            "alert_date_range_start":      safe_stats.get("alert_date_range_start"),
            "alert_date_range_end":        safe_stats.get("alert_date_range_end"),
        }
        alert_payload["_customer_background"] = enrichment_result.get(
            "customer_background", {}
        )

        # BUG #3 FIX: overwrite stale JSON counts with DB-derived values
        txn_rows = enrichment_result["pii_sealed"].get("txn_table_rows", [])
        alert_payload["transactions"]["transaction_count"] = len(txn_rows)
        alert_payload["transactions"]["total_amount"] = round(
            sum(
                float(r["amount"]) for r in txn_rows
                if r.get("txn_type") == "credit"
            ), 2,
        )

        append_audit_event(case_id, "ENRICHMENT_COMPLETED", {
            "enriched": True,
            "customer_id": alert_payload.get("customer_id"),
            "avg_monthly_deposits_12m": safe_stats.get("avg_monthly_deposits_12m"),
            "deviation_pct": safe_stats.get("deviation_from_baseline_pct"),
            "unique_counterparties": safe_stats.get("unique_counterparties_count"),
            "new_counterparties": safe_stats.get("new_counterparties_count"),
            "db_transaction_count": len(txn_rows),
        })
        update_case(case_id, alert_payload=alert_payload)
    else:
        append_audit_event(case_id, "ENRICHMENT_SKIPPED", {
            "enriched": False,
            "reason": enrichment_result.get("error") or "No enrichment data found.",
        })

    # ── Pipeline ─────────────────────────────────────────────────────────
    try:
        from .regulation_engine import get_registry
        alert_payload["_registry_config"] = get_registry()
        result = service.process_alert(alert_payload)
    except Exception as exc:
        update_case(case_id, status="FAILED")
        append_audit_event(case_id, "CASE_FAILED", {
            "error": str(exc), "failed_at": utc_now()
        })
        raise HTTPException(
            status_code=500, detail=f"Case processing failed: {exc}"
        ) from exc

    update_case(
        case_id,
        alert_id=alert_payload["alert_id"],
        status=result["status"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        masked_alert_payload=result["masked_alert"],
        evidence_pack=result["evidence_pack"],
        retrieval_payload=result["retrieval_payload"],
        prompt_payload=result["prompt_payload"],
        validation_payload=result["validation_payload"],
        final_sar=result["final_sar"],
        enrichment_payload=enrichment_result,
    )

    for event in result["audit_events"]:
        append_audit_event(case_id, event["event_type"], serialise(event["payload"]))

    case_record = get_case(case_id)
    if case_record is None:
        raise HTTPException(
            status_code=500, detail="Case was created but could not be reloaded."
        )
    return build_case_response(case_record)


@app.get("/cases/{case_id}")
def get_case_detail(
    case_id: str,
    _: dict[str, str] = Depends(get_current_user),
) -> dict[str, Any]:
    case_record = get_case(case_id)
    if case_record is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return build_case_response(case_record)


@app.get("/cases/{case_id}/audit")
def get_case_audit(
    case_id: str,
    _: dict[str, str] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    case_record = get_case(case_id)
    if case_record is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return serialise(get_audit_events(case_id))


@app.post("/cases/{case_id}/review")
def submit_review(
    case_id: str,
    request: ReviewRequest,
    _: dict[str, str] = Depends(get_current_user),
) -> dict[str, Any]:
    case_record = get_case(case_id)
    if case_record is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    final_sar          = case_record.get("final_sar") or {}
    original_narrative = final_sar.get("narrative", "")
    updated_narrative  = request.edited_narrative or original_narrative
    review_status      = "APPROVED" if request.decision == "APPROVE" else "REJECTED"
    review_timestamp   = utc_now()
    edit_diff          = build_text_diff(original_narrative, updated_narrative)

    analyst_review = {
        "analyst_id":  request.analyst_id,
        "decision":    request.decision,
        "comment":     request.comment,
        "submitted_at": review_timestamp,
        "edit_diff":   edit_diff,
        "edited":      updated_narrative != original_narrative,
    }
    final_sar["narrative"]   = updated_narrative
    final_sar["status"]      = review_status
    final_sar["reviewed_at"] = review_timestamp

    update_case(case_id, status=review_status, analyst_review=analyst_review, final_sar=final_sar)

    if request.decision == "APPROVE":
        _alert_payload = case_record.get("alert_payload") or {}
        _evidence_pack = case_record.get("evidence_pack") or {}
        _rule_summary = _evidence_pack.get("rule_summary") or []
        _txn = _alert_payload.get("transactions") or {}

        _narrative = updated_narrative or ""
        _narrative_summary = _narrative[:300] + "..." if len(_narrative) > 300 else _narrative

        record_customer_sar_approval(
            customer_id=str(_alert_payload.get("customer_id") or ""),
            case_id=case_id,
            alert_id=str(_alert_payload.get("alert_id") or ""),
            alert_type=str(_alert_payload.get("alert_type") or ""),
            risk_level=str(case_record.get("risk_level") or ""),
            risk_score=float(case_record.get("risk_score") or 0),
            total_amount=float(_txn.get("total_amount") or 0),
            destination_country=str(_txn.get("destination_country") or ""),
            approved_by=request.analyst_id,
            rules_triggered=[r["rule_id"] for r in _rule_summary if "rule_id" in r],
            narrative_summary=_narrative_summary,
        )

        append_audit_event(case_id, "SAR_HISTORY_RECORDED", {
            "customer_id": _alert_payload.get("customer_id"),
            "recorded_at": utc_now(),
        })

    # Record analyst disposition for the historical feedback loop.
    # This is what Signal 6 in the false alert filter learns from.
    # Every approve/reject decision improves future false alert scoring
    # for the same rule combination and customer profile.
    rule_summary = (case_record.get("evidence_pack") or {}).get("rule_summary", [])
    rule_ids_from_case = sorted([r["rule_id"] for r in rule_summary if "rule_id" in r])
    customer_profile_from_case = (
        (case_record.get("alert_payload") or {}).get("customer_profile", "")
    )
    disposition_value = "TRUE_POSITIVE" if request.decision == "APPROVE" else "FALSE_POSITIVE"

    record_alert_disposition(
        case_id=case_id,
        rule_ids=rule_ids_from_case,
        customer_profile=customer_profile_from_case,
        disposition=disposition_value,
        disposed_by=request.analyst_id or "unknown_analyst",
    )
    append_audit_event(case_id, "DISPOSITION_RECORDED", {
        "disposition": disposition_value,
        "rule_ids": rule_ids_from_case,
        "customer_profile": customer_profile_from_case,
        "disposed_by": request.analyst_id,
    })

    append_audit_event(case_id, "ANALYST_REVIEW_SUBMITTED", analyst_review)

    if request.decision == "APPROVE":
        append_audit_event(case_id, "EXPORT_TRIGGERED", {
            "status":       "LOCAL_EXPORT_READY",
            "comment":      "Case approved and ready for downstream export.",
            "triggered_at": review_timestamp,
        })

    refreshed_case = get_case(case_id)
    if refreshed_case is None:
        raise HTTPException(status_code=500, detail="Reviewed case could not be reloaded.")
    return build_case_response(refreshed_case)


@app.post("/cases/{case_id}/replay", response_model=ReplayResponse)
def replay_case(
    case_id: str,
    _: dict[str, str] = Depends(get_current_user),
) -> ReplayResponse:
    case_record = get_case(case_id)
    if case_record is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    replay_payload = service.replay_case(serialise(case_record))
    update_case(case_id, replay_payload=replay_payload)
    append_audit_event(case_id, "CASE_REPLAYED", serialise(replay_payload))
    return ReplayResponse(**serialise(replay_payload))


@app.get("/cases/{case_id}/export/pdf")
def export_case_pdf(
    case_id: str,
    _: dict[str, str] = Depends(get_current_user),
) -> StreamingResponse:
    case_record = get_case(case_id)
    if case_record is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    pdf_bytes = _build_pdf(case_record)
    stream = BytesIO(pdf_bytes)
    return StreamingResponse(
        stream,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=SAR_{case_id}.pdf"},
    )


@app.post("/cases/{case_id}/escalate")
def escalate_triage_case(
    case_id: str,
    current_user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Escalates a PENDING_TRIAGE case to full pipeline processing.
    Called by analyst from the triage queue when they decide the
    borderline alert warrants full SAR generation.
    Runs the complete enrich -> LLM -> narrative pipeline.
    """
    case_record = get_case(case_id)
    if case_record is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    if case_record.get("status") != "PENDING_TRIAGE":
        raise HTTPException(
            status_code=409,
            detail=f"Case status is '{case_record.get('status')}'. Only PENDING_TRIAGE cases can be escalated.",
        )

    alert_payload = dict(case_record.get("alert_payload") or {})

    append_audit_event(case_id, "TRIAGE_ESCALATED", {
        "escalated_by": current_user["username"],
        "escalated_at": utc_now(),
        "reason": "Analyst manually escalated borderline alert to full pipeline",
    })

    # Run enrichment
    enrichment_result = enrich_case(alert_payload)
    if enrichment_result.get("enriched"):
        safe_stats = enrichment_result["safe_stats"]
        alert_payload["customer_financials"] = {
            "declared_monthly_income": safe_stats.get("declared_monthly_income"),
            "avg_monthly_deposits_12m": safe_stats.get("avg_monthly_deposits_12m"),
            "historical_baseline_txn_count": safe_stats.get("historical_baseline_txn_count"),
            "deviation_from_baseline_pct": safe_stats.get("deviation_from_baseline_pct"),
        }
        alert_payload["_enrichment_context"] = {
            "unique_counterparties_count": safe_stats.get("unique_counterparties_count"),
            "new_counterparties_count": safe_stats.get("new_counterparties_count"),
            "has_prior_relationship": safe_stats.get("has_prior_relationship"),
            "alert_date_range_start": safe_stats.get("alert_date_range_start"),
            "alert_date_range_end": safe_stats.get("alert_date_range_end"),
        }
        alert_payload["_customer_background"] = enrichment_result.get(
            "customer_background", {}
        )
        txn_rows = enrichment_result["pii_sealed"].get("txn_table_rows", [])
        alert_payload["transactions"]["transaction_count"] = len(txn_rows)
        alert_payload["transactions"]["total_amount"] = round(
            sum(float(r["amount"]) for r in txn_rows if r.get("txn_type") == "credit"), 2
        )
        update_case(case_id, alert_payload=alert_payload)

    # Run full pipeline
    try:
        alert_payload["_registry_config"] = get_registry()
        result = service.process_alert(alert_payload)
    except Exception as exc:
        update_case(case_id, status="FAILED")
        append_audit_event(case_id, "CASE_FAILED", {
            "error": str(exc), "failed_at": utc_now()
        })
        raise HTTPException(status_code=500, detail=f"Pipeline failed: {exc}") from exc

    update_case(
        case_id,
        status=result["status"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        masked_alert_payload=result["masked_alert"],
        evidence_pack=result["evidence_pack"],
        retrieval_payload=result["retrieval_payload"],
        prompt_payload=result["prompt_payload"],
        validation_payload=result["validation_payload"],
        final_sar=result["final_sar"],
        enrichment_payload=enrichment_result,
    )
    for event in result["audit_events"]:
        append_audit_event(case_id, event["event_type"], serialise(event["payload"]))

    refreshed = get_case(case_id)
    if refreshed is None:
        raise HTTPException(status_code=500, detail="Case could not be reloaded after escalation.")
    return build_case_response(refreshed)


@app.post("/cases/{case_id}/close-false-positive")
def close_as_false_positive(
    case_id: str,
    current_user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Closes a PENDING_TRIAGE case as a confirmed false positive.
    Records the disposition for the historical feedback loop.
    Called by analyst from the triage queue when they decide
    the borderline alert is not worth escalating.
    """
    case_record = get_case(case_id)
    if case_record is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    if case_record.get("status") not in ("PENDING_TRIAGE", "AUTO_CLOSED_FALSE_POSITIVE"):
        raise HTTPException(
            status_code=409,
            detail=f"Case status is '{case_record.get('status')}'. Cannot close as false positive.",
        )

    rule_summary = (case_record.get("evidence_pack") or {}).get("rule_summary", [])
    rule_ids = sorted([r["rule_id"] for r in rule_summary if "rule_id" in r])
    customer_profile = (case_record.get("alert_payload") or {}).get("customer_profile", "")

    record_alert_disposition(
        case_id=case_id,
        rule_ids=rule_ids,
        customer_profile=customer_profile,
        disposition="FALSE_POSITIVE",
        disposed_by=current_user["username"],
    )
    update_case(case_id, status="CONFIRMED_FALSE_POSITIVE")
    append_audit_event(case_id, "CONFIRMED_FALSE_POSITIVE", {
        "confirmed_by": current_user["username"],
        "confirmed_at": utc_now(),
        "rule_ids": rule_ids,
        "customer_profile": customer_profile,
    })

    return {
        "status": "CONFIRMED_FALSE_POSITIVE",
        "case_id": case_id,
        "message": (
            "Case closed as confirmed false positive. "
            "Disposition recorded for feedback loop. "
            "Future alerts with this rule combination and profile "
            "will score lower and be more likely to auto-close."
        ),
    }


# ════════════════════════════════════════════════════════
# REGULATION AUTHORING ENDPOINTS
# ════════════════════════════════════════════════════════

@app.post("/regulations/upload")
def upload_regulation(
    request: RegulationUploadRequest,
    current_user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Stage a regulation by extracting threshold changes and gap report."""
    if current_user["role"] not in ("manager", "admin"):
        raise HTTPException(
            status_code=403,
            detail="Only managers and admins can upload regulations.",
        )

    file_bytes = None
    if request.file_bytes_b64:
        import base64 as _b64

        try:
            file_bytes = _b64.b64decode(request.file_bytes_b64)
        except Exception as exc:
            raise HTTPException(
                status_code=422,
                detail=f"Could not decode file_bytes_b64: {exc}",
            )

    result = process_regulation_document(
        document_text=request.document_text or "",
        source_filename=request.source_filename,
        file_bytes=file_bytes,
    )

    if not result.get("success"):
        raise HTTPException(
            status_code=422,
            detail=result.get("error", "Regulation processing failed."),
        )

    doc_text = request.document_text or ""
    if not doc_text and file_bytes:
        from .regulation_engine import extract_text_from_bytes

        try:
            doc_text = extract_text_from_bytes(file_bytes, request.source_filename)
        except Exception:
            doc_text = ""

    if doc_text:
        ingest_regulation_document(
            document_text=doc_text,
            asset_type=request.asset_type,
            source_filename=request.source_filename,
            regulation_name=request.source_filename,
        )

    if not result.get("ready_for_staging"):
        return {
            "status": "NO_ACTIONABLE_CHANGES",
            "message": (
                "The document was ingested into the knowledge base but no "
                "threshold parameters were detected that differ from current "
                "rules.yaml values. No staging entry created."
            ),
            "total_chunks": result.get("total_chunks", 0),
            "compliance_chunks": result.get("compliance_chunks", 0),
            "extracted_params": result.get("extracted_params", {}),
            "rule_types": result.get("rule_types_detected", []),
        }

    staging_id = str(uuid4())
    create_staging_entry(
        staging_id=staging_id,
        asset_type=request.asset_type,
        source_file=request.source_filename,
        proposed_rules=[],
        dry_run_result={},
        citation_checks={},
        regulation_list=[request.source_filename],
        conclusion_regulation="",
        additional_prompt_context="",
        document_text=doc_text,
        threshold_changes=result.get("threshold_changes", []),
        gap_report=result.get("gap_report"),
        rule_types_detected=result.get("rule_types_detected", []),
        extracted_params=result.get("extracted_params", {}),
    )

    actual_changes = [c for c in result.get("threshold_changes", []) if c.get("is_change")]

    return {
        "status": "STAGED_FOR_REVIEW",
        "staging_id": staging_id,
        "asset_type": request.asset_type,
        "source_file": request.source_filename,
        "total_chunks": result.get("total_chunks", 0),
        "compliance_chunks": result.get("compliance_chunks", 0),
        "extracted_params": result.get("extracted_params", {}),
        "threshold_changes": result.get("threshold_changes", []),
        "actual_changes_count": len(actual_changes),
        "rule_types_detected": result.get("rule_types_detected", []),
        "gap_report": result.get("gap_report"),
        "message": (
            f"{len(actual_changes)} threshold parameter(s) staged for review. "
            f"Use POST /regulations/staging/{staging_id}/review to approve or reject."
            + (
                " Gap report generated - new rule requirements detected that need manual implementation."
                if result.get("gap_report")
                else ""
            )
        ),
    }


@app.get("/regulations/staging")
def list_staged_regulations(
    status: str | None = None,
    _: dict[str, str] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    return serialise(list_staging_entries(status))


@app.get("/regulations/staging/{staging_id}")
def get_staged_regulation(
    staging_id: str,
    _: dict[str, str] = Depends(get_current_user),
) -> dict[str, Any]:
    entry = get_staging_entry(staging_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Staging entry not found.")
    return serialise(entry)


@app.post("/regulations/staging/{staging_id}/review")
def review_staged_regulation(
    staging_id: str,
    request: StagingReviewRequest,
    current_user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    if current_user["role"] not in ("manager", "admin"):
        raise HTTPException(
            status_code=403,
            detail="Only managers and admins can approve regulations.",
        )

    entry = get_staging_entry(staging_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Staging entry not found.")

    if entry["status"] != "PROPOSED":
        raise HTTPException(
            status_code=409,
            detail=f"Staging entry is already '{entry['status']}'. Cannot review again.",
        )

    if request.decision == "REJECT":
        update_staging_status(
            staging_id=staging_id,
            status="REJECTED",
            reviewed_by=current_user["username"],
            rejection_reason=request.rejection_reason,
        )
        return {
            "status": "REJECTED",
            "staging_id": staging_id,
            "reviewed_by": current_user["username"],
            "message": "Regulation rejected. No changes applied to rules.yaml.",
        }

    asset_type = entry["asset_type"]

    raw_changes = entry.get("threshold_changes") or []
    if isinstance(raw_changes, str):
        raw_changes = json.loads(raw_changes)

    if request.approved_changes:
        raw_changes = [c for c in raw_changes if c.get("key") in request.approved_changes]

    apply_result = apply_threshold_updates(raw_changes)

    try:
        from rag_pipeline.rule_engine import load_rule_config as _rc1

        _rc1.cache_clear()
    except Exception:
        pass
    try:
        load_rule_config.cache_clear()
    except Exception:
        pass

    # Pull regulation data from staging entry
    raw_reg_list = entry.get("regulation_list")
    if isinstance(raw_reg_list, str):
        import json as _json
        regulation_list = _json.loads(raw_reg_list) or [entry["source_file"]]
    elif raw_reg_list:
        regulation_list = raw_reg_list
    else:
        regulation_list = [entry["source_file"]]
    conclusion_regulation = entry.get("conclusion_regulation") or ""
    additional_prompt_context = entry.get("additional_prompt_context") or ""

    activate_asset_type_in_registry(
        asset_type=asset_type,
        regulations=regulation_list,
        conclusion_regulation=conclusion_regulation,
        additional_prompt_context=additional_prompt_context,
        activated_by=current_user["username"],
    )

    update_staging_status(
        staging_id=staging_id,
        status="PROMOTED",
        reviewed_by=current_user["username"],
    )

    # Release and reprocess all quarantined alerts
    released = release_quarantined_alerts(asset_type)
    reprocessed: list[dict[str, Any]] = []

    for row in released:
        quarantine_id = row["quarantine_id"]
        try:
            alert_payload = (
                dict(row["alert_payload"])
                if isinstance(row["alert_payload"], dict)
                else json.loads(row["alert_payload"])
            )
            # Reprocess via full pipeline
            new_case_id = str(uuid4())
            new_masked = mask_alert(alert_payload)
            create_case(new_case_id, alert_payload, new_masked)

            enrichment_result = enrich_case(alert_payload)
            if enrichment_result.get("enriched"):
                safe_stats = enrichment_result["safe_stats"]
                alert_payload["customer_financials"] = {
                    "declared_monthly_income":       safe_stats.get("declared_monthly_income"),
                    "avg_monthly_deposits_12m":      safe_stats.get("avg_monthly_deposits_12m"),
                    "historical_baseline_txn_count": safe_stats.get("historical_baseline_txn_count"),
                    "deviation_from_baseline_pct":   safe_stats.get("deviation_from_baseline_pct"),
                }
                alert_payload["_enrichment_context"] = {
                    "unique_counterparties_count": safe_stats.get("unique_counterparties_count"),
                    "new_counterparties_count":    safe_stats.get("new_counterparties_count"),
                    "has_prior_relationship":      safe_stats.get("has_prior_relationship"),
                    "alert_date_range_start":      safe_stats.get("alert_date_range_start"),
                    "alert_date_range_end":        safe_stats.get("alert_date_range_end"),
                }
                txn_rows = enrichment_result["pii_sealed"].get("txn_table_rows", [])
                alert_payload["transactions"]["transaction_count"] = len(txn_rows)
                alert_payload["transactions"]["total_amount"] = round(
                    sum(float(r["amount"]) for r in txn_rows if r.get("txn_type") == "credit"), 2
                )

            result = service.process_alert(alert_payload)
            update_case(
                new_case_id,
                alert_id=alert_payload["alert_id"],
                status=result["status"],
                risk_score=result["risk_score"],
                risk_level=result["risk_level"],
                masked_alert_payload=result["masked_alert"],
                evidence_pack=result["evidence_pack"],
                retrieval_payload=result["retrieval_payload"],
                prompt_payload=result["prompt_payload"],
                validation_payload=result["validation_payload"],
                final_sar=result["final_sar"],
                enrichment_payload=enrichment_result,
            )
            for event in result["audit_events"]:
                append_audit_event(new_case_id, event["event_type"], serialise(event["payload"]))

            reprocessed.append({
                "quarantine_id": quarantine_id,
                "alert_id": alert_payload.get("alert_id"),
                "new_case_id": new_case_id,
                "status": "REPROCESSED",
                "risk_level": result["risk_level"],
            })
        except Exception as exc:
            reprocessed.append({
                "quarantine_id": quarantine_id,
                "alert_id": alert_payload.get("alert_id", "UNKNOWN"),
                "status": "REPROCESS_FAILED",
                "error": str(exc),
            })

    return {
        "status": "APPROVED_AND_PROMOTED",
        "staging_id": staging_id,
        "asset_type": asset_type,
        "reviewed_by": current_user["username"],
        "threshold_updates_applied": apply_result.get("applied", []),
        "threshold_updates_skipped": apply_result.get("skipped", []),
        "total_applied": apply_result.get("total_applied", 0),
        "quarantined_alerts_released": len(released),
        "reprocessed": reprocessed,
        "gap_report": entry.get("gap_report"),
        "message": (
            f"Regulatory framework for {asset_type} is now ACTIVE. "
            f"{apply_result.get('total_applied', 0)} threshold value(s) updated in rules.yaml. "
            f"Rule engine cache cleared. "
            f"{len(released)} quarantined alerts reprocessed."
            + (
                " Gap report present - new rule requirements still need manual implementation."
                if entry.get("gap_report")
                else ""
            )
        ),
    }


@app.get("/regulations/registry")
def get_regulation_registry(
    _: dict[str, str] = Depends(get_current_user),
) -> dict[str, Any]:
    return get_registry()


@app.get("/regulations/quarantine")
def get_quarantine_queue(
    _: dict[str, str] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    return serialise(list_quarantine_queue())