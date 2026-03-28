from __future__ import annotations

"""
enrichment.py — Database-backed KYC and transaction enrichment layer.

This module is the ONLY place in the system where real transaction records
and KYC data are fetched from PostgreSQL for AML purposes.

Architecture:
    enrich_case() returns two strictly separated objects:

    safe_stats  — LLM-safe anonymised statistics.
                  Goes into alert_payload["customer_financials"].
                  Never contains customer name, account numbers, or raw IDs.

    pii_sealed  — PII-containing fields and transaction ID buckets.
                  Never crosses the PII boundary into the LLM prompt.
                  Used ONLY by:
                    1. _build_sentence_traceability() for real TXN ID attachment
                    2. _build_pdf() for transaction table rendering and name reinsertion

PII Boundary guarantee:
    The LLM receives safe_stats fields as plain text data lines.
    The LLM never receives customer name, account numbers, raw TXN IDs,
    counterparty names, or any field from pii_sealed.

Alert window guarantee:
    If alert_window_start and alert_window_end are provided in the alert JSON
    (from the TMS detection event), enrichment uses these as IMMUTABLE boundaries.
    This prevents late-filing date drift — a SAR filed on April 2 for suspicious
    activity on March 24-26 will always describe March 24-26 activity only.
    If not provided, the enrichment falls back to computing the window from
    the latest DB transaction timestamp minus time_window_days.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from .database import (
    get_accounts_for_customer,
    get_full_customer_kyc,
    get_customer_sar_history,
    get_customer_sar_summary,
    get_latest_transaction_timestamp,
    get_transactions_in_range,
)

# Reporting threshold — transactions below this in structuring band
# are flagged as potential structuring.
# This matches the default in rules.yaml thresholds.reporting_threshold
DEFAULT_REPORTING_THRESHOLD = 1_000_000.0


def _safe_dt(value: Any, fallback: datetime) -> datetime:
    """Convert a value to timezone-aware datetime, returning fallback on failure."""
    if value is None:
        return fallback
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts
    except (ValueError, TypeError):
        return fallback


def _fmt_date(dt: datetime) -> str:
    """Format a datetime as analyst-readable date string."""
    return dt.strftime("%d %b %Y")


def enrich_case(alert_json: dict[str, Any]) -> dict[str, Any]:
    """
    Main enrichment entry point.

    Input:
        alert_json — the raw alert payload from POST /cases.
                     Must contain customer_id.
                     May optionally contain alert_window_start and alert_window_end.

    Now also:
    - Fetches KYC fields (name, profile, account_type) from DB
    - Populates missing alert fields in-place
    - Builds customer_background block with SAR history
    """
    customer_id = str(alert_json.get("customer_id", "")).strip()
    now_utc = datetime.now(timezone.utc)

    try:
        return _enrich_case_internal(alert_json, customer_id, now_utc)
    except Exception as exc:
        return {
            "safe_stats": {},
            "pii_sealed": {},
            "customer_background": {},
            "enriched": False,
            "error": str(exc),
        }


def _enrich_case_internal(
    alert_json: dict[str, Any],
    customer_id: str,
    now_utc: datetime,
) -> dict[str, Any]:

    # ── Step 1: Fetch full KYC record ────────────────────────────────────
    customer = get_full_customer_kyc(customer_id)
    if not customer:
        return {
            "safe_stats": {},
            "pii_sealed": {},
            "customer_background": {},
            "enriched": False,
            "error": (
                f"Customer {customer_id} not found in database. "
                "Ensure seed_data.py has been run."
            ),
        }

    # ── Step 2: Populate missing alert fields from DB ────────────────────
    # Alert JSON no longer carries these fields.
    alert_json["customer_name"] = str(customer["name"])
    alert_json["account_type"] = (
        str(customer["account_types"][0])
        if customer.get("account_types")
        else "unknown"
    )
    alert_json["customer_profile"] = str(customer.get("occupation") or "Unknown")

    # ── Step 3: Fetch all accounts for this customer ─────────────────────
    accounts = get_accounts_for_customer(customer_id)
    if not accounts:
        return {
            "safe_stats": {},
            "pii_sealed": {},
            "customer_background": {},
            "enriched": False,
            "error": f"No accounts found for customer {customer_id}.",
        }

    account_ids = [str(a["account_id"]) for a in accounts]

    # ── Step 4: Determine alert window boundaries ─────────────────────────
    # Priority 1: explicit TMS-provided boundaries from alert JSON
    # Priority 2: compute from latest DB transaction minus time_window_days
    window_start_raw = alert_json.get("alert_window_start")
    window_end_raw   = alert_json.get("alert_window_end")

    if window_start_raw and window_end_raw:
        # TMS gave explicit boundaries — use them as-is
        reference_end = _safe_dt(window_end_raw, now_utc)
        alert_start   = _safe_dt(window_start_raw, now_utc)
    else:
        # Fallback: anchor to latest DB transaction
        # WARNING: inaccurate if filing is delayed and new transactions exist
        latest_ts = get_latest_transaction_timestamp(account_ids)
        reference_end = _safe_dt(latest_ts, now_utc)
        alert_window_days = int(
            alert_json.get("transactions", {}).get("time_window_days") or 3
        )
        alert_start = reference_end - timedelta(days=alert_window_days)

    # ── Step 5: Fetch 12-month transaction history ────────────────────────
    lookback_start = reference_end - timedelta(days=365)
    all_12m = get_transactions_in_range(account_ids, lookback_start, reference_end)

    # ── Step 6: Isolate alert-window transactions ─────────────────────────
    # These are the ONLY transactions that constitute the suspicious activity.
    # Transactions before alert_start or after reference_end are excluded.
    alert_window_txns = [
        t for t in all_12m
        if _safe_dt(t["timestamp"], now_utc) >= alert_start
        and _safe_dt(t["timestamp"], now_utc) <= reference_end
    ]

    # ── Step 7: Compute 12-month baseline from pre-alert history ─────────
    # Use only credits (inbound) for deposit baseline calculation.
    # Exclude the alert window itself to avoid contaminating the baseline.
    pre_alert_txns = [
        t for t in all_12m
        if _safe_dt(t["timestamp"], now_utc) < alert_start
        and t["txn_type"] == "credit"
    ]

    # Group pre-alert credits by month to compute monthly average
    monthly_credits: dict[str, float] = {}
    for t in pre_alert_txns:
        ts = _safe_dt(t["timestamp"], now_utc)
        month_key = ts.strftime("%Y-%m")
        monthly_credits[month_key] = monthly_credits.get(month_key, 0.0) + float(t["amount"])

    avg_monthly_deposits = (
        round(sum(monthly_credits.values()) / len(monthly_credits), 2)
        if monthly_credits else 0.0
    )

    # ── Step 8: Compute deviation from baseline ───────────────────────────
    alert_total = float(
        alert_json.get("transactions", {}).get("total_amount")
        or sum(float(t["amount"]) for t in alert_window_txns if t["txn_type"] == "credit")
        or 0.0
    )

    deviation_pct = (
        round(((alert_total - avg_monthly_deposits) / avg_monthly_deposits) * 100, 1)
        if avg_monthly_deposits > 0
        else None
    )

    # ── Step 9: Counterparty intelligence ────────────────────────────────
    # Counterparties seen during the alert window
    alert_counterparties = {
        str(t["counterparty"])
        for t in alert_window_txns
        if t.get("counterparty")
    }

    # Counterparties seen in the 12 months BEFORE the alert window
    prior_counterparties = {
        str(t["counterparty"])
        for t in pre_alert_txns
        if t.get("counterparty")
    }

    # New counterparties never seen before — layering indicator
    new_counterparties = alert_counterparties - prior_counterparties

    # ── Step 10: Build evidence buckets ──────────────────────────────────
    # These contain real transaction IDs from the DB.
    # Used ONLY for sentence traceability — never passed to LLM.
    reporting_threshold = float(
        alert_json.get("transactions", {}).get("reporting_threshold")
        or DEFAULT_REPORTING_THRESHOLD
    )
    destination = str(
        alert_json.get("transactions", {}).get("destination_country") or ""
    ).upper()

    uae_transfers = [
        str(t["txn_id"]) for t in alert_window_txns
        if t["txn_type"] == "debit"
        and str(t.get("country", "")).upper() == destination
    ]

    structuring_txns = [
        str(t["txn_id"]) for t in alert_window_txns
        if float(t["amount"]) < reporting_threshold
    ]

    high_velocity_txns = [str(t["txn_id"]) for t in alert_window_txns]

    # ── Step 11: Historical transaction count per month ───────────────────
    # Count all transaction types in pre-alert history for baseline count
    pre_alert_all = [
        t for t in all_12m
        if _safe_dt(t["timestamp"], now_utc) < alert_start
    ]
    monthly_counts: dict[str, int] = {}
    for t in pre_alert_all:
        ts = _safe_dt(t["timestamp"], now_utc)
        month_key = ts.strftime("%Y-%m")
        monthly_counts[month_key] = monthly_counts.get(month_key, 0) + 1

    historical_baseline_txn_count = (
        round(sum(monthly_counts.values()) / len(monthly_counts))
        if monthly_counts else 0
    )

    # ── Step 12: Build transaction details for PDF table ─────────────────
    # These are the actual suspicious transaction rows for the PDF.
    # Contains PII-adjacent data (exact amounts, counterparties, dates).
    # Stored in pii_sealed — never crosses PII boundary.
    txn_table_rows = [
        {
            "txn_id":      str(t["txn_id"]),
            "date":        _fmt_date(_safe_dt(t["timestamp"], now_utc)),
            "amount":      float(t["amount"]),
            "txn_type":    t["txn_type"],
            "country":     str(t.get("country") or "INDIA"),
            "counterparty": str(t.get("counterparty") or "N/A"),
        }
        for t in alert_window_txns
    ]

    # ── Step 13: Account tenure ───────────────────────────────────────────
    earliest_account = min(
        (a for a in accounts if a.get("opened_date")),
        key=lambda a: a["opened_date"],
        default=None,
    )
    _raw_opened = earliest_account.get("opened_date") if earliest_account else None
    if _raw_opened:
        if not isinstance(_raw_opened, datetime):
            from datetime import date as _date
            if isinstance(_raw_opened, _date):
                _raw_opened = datetime(_raw_opened.year, _raw_opened.month, _raw_opened.day, tzinfo=timezone.utc)
        account_opened_date = _raw_opened.strftime("%d %b %Y")
    else:
        account_opened_date = "N/A"

    # ── Step 14: Customer SAR history ─────────────────────────────────────
    sar_history = get_customer_sar_history(customer_id, limit=10)
    sar_summary = get_customer_sar_summary(customer_id)

    sar_timeline = [
        {
            "case_id": str(h["case_id"]),
            "alert_id": str(h["alert_id"]),
            "alert_type": str(h["alert_type"]),
            "risk_level": str(h["risk_level"]),
            "risk_score": float(h["risk_score"] or 0),
            "total_amount": float(h["total_amount"] or 0),
            "destination_country": str(h.get("destination_country") or "N/A"),
            "approved_by": str(h["approved_by"]),
            "approved_at": _fmt_date(_safe_dt(h["approved_at"], now_utc)),
            "rules_triggered": h.get("rules_triggered") or [],
        }
        for h in sar_history
    ]

    # ── Step 15: Bank relationship ────────────────────────────────────────
    relationship_since_raw = customer.get("relationship_since")
    if relationship_since_raw:
        from datetime import date as _date

        if isinstance(relationship_since_raw, _date):
            rel_since_str = relationship_since_raw.strftime("%d %b %Y")
            rel_years = round((now_utc.date() - relationship_since_raw).days / 365.25, 1)
        else:
            rel_since_str = str(relationship_since_raw)
            rel_years = None
    else:
        rel_since_str = "N/A"
        rel_years = None

    # ── Step 16: KYC flags ────────────────────────────────────────────────
    kyc_last_reviewed_raw = customer.get("kyc_last_reviewed")
    kyc_review_due_raw = customer.get("kyc_review_due")

    kyc_last_reviewed_str = (
        kyc_last_reviewed_raw.strftime("%d %b %Y")
        if kyc_last_reviewed_raw
        else "N/A"
    )
    kyc_review_due_str = (
        kyc_review_due_raw.strftime("%d %b %Y")
        if kyc_review_due_raw
        else "N/A"
    )

    # ── Assemble outputs ──────────────────────────────────────────────────

    safe_stats: dict[str, Any] = {
        # These go into alert_payload["customer_financials"]
        # and flow into the LLM prompt as plain text data lines.
        # NO PII here.
        "declared_monthly_income":     float(customer["monthly_income"] or 0),
        "avg_monthly_deposits_12m":    avg_monthly_deposits,
        "historical_baseline_txn_count": historical_baseline_txn_count,
        "deviation_from_baseline_pct": deviation_pct,

        # These go into the prompt as additional context lines.
        "unique_counterparties_count": len(alert_counterparties),
        "prior_counterparties_count":  len(prior_counterparties),
        "new_counterparties_count":    len(new_counterparties),
        "has_prior_relationship":      len(prior_counterparties) > 0,
        "alert_date_range_start": _fmt_date(alert_start),
        "alert_date_range_end":   _fmt_date(reference_end),
        "is_repeat_sar_customer": sar_summary["is_repeat_sar_customer"],
        "prior_sar_count": int(sar_summary["total_sars_filed"]),
        "relationship_years": rel_years,
        "kyc_risk_rating": str(customer.get("risk_rating") or "LOW"),
        "pep_flag": bool(customer.get("pep_flag") or False),
        "adverse_media_flag": bool(customer.get("adverse_media_flag") or False),
    }

    pii_sealed: dict[str, Any] = {
        "customer_name":       str(customer["name"]),
        "occupation":          str(customer.get("occupation") or "N/A"),
        "risk_rating":         str(customer.get("risk_rating") or "N/A"),
        "account_opened_date": account_opened_date,
        "nationality":         str(customer.get("nationality") or "N/A"),
        "pep_flag":            bool(customer.get("pep_flag") or False),
        "adverse_media_flag":  bool(customer.get("adverse_media_flag") or False),
        "kyc_last_reviewed":   kyc_last_reviewed_str,
        "kyc_review_due":      kyc_review_due_str,
        "relationship_since":  rel_since_str,
        "relationship_type":   str(customer.get("relationship_type") or "STANDARD"),

        "txn_buckets": {
            "high_velocity_txns": high_velocity_txns,
            "uae_transfers":      uae_transfers,
            "structuring_txns":   structuring_txns,
        },
        "txn_table_rows": txn_table_rows,
        "alert_window_start_fmt": _fmt_date(alert_start),
        "alert_window_end_fmt":   _fmt_date(reference_end),
        "sar_timeline": sar_timeline,
        "sar_summary": sar_summary,
    }

    customer_background: dict[str, Any] = {
        "prior_sar_count": int(sar_summary["total_sars_filed"]),
        "is_repeat_sar_customer": sar_summary["is_repeat_sar_customer"],
        "most_recent_sar_date": (
            _fmt_date(_safe_dt(sar_summary["most_recent_sar_date"], now_utc))
            if sar_summary["most_recent_sar_date"]
            else None
        ),
        "total_suspicious_amount": float(sar_summary["total_suspicious_amount"] or 0),
        "alert_types_seen": sar_summary["alert_types_seen"] or [],
        "countries_involved": sar_summary["countries_involved"] or [],
        "relationship_years": rel_years,
        "kyc_risk_rating": str(customer.get("risk_rating") or "LOW"),
        "pep_flag": bool(customer.get("pep_flag") or False),
        "adverse_media_flag": bool(customer.get("adverse_media_flag") or False),
        "account_count": int(customer.get("total_accounts") or 1),
    }

    return {
        "safe_stats": safe_stats,
        "pii_sealed": pii_sealed,
        "customer_background": customer_background,
        "enriched":   True,
        "error":      None,
    }