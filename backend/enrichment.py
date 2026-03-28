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
    get_customer,
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

    Returns:
        {
            "safe_stats":   dict — LLM-safe statistics for prompt injection,
            "pii_sealed":   dict — PII fields and TXN buckets for PDF and traceability,
            "enriched":     bool — True if DB records were found, False if not found,
            "error":        str | None — Error message if enrichment failed partially,
        }

    On failure:
        Returns enriched=False with empty safe_stats and pii_sealed.
        The pipeline continues without enrichment — no data is fabricated.
    """
    customer_id = str(alert_json.get("customer_id", "")).strip()
    now_utc = datetime.now(timezone.utc)

    try:
        return _enrich_case_internal(alert_json, customer_id, now_utc)
    except Exception as exc:
        return {
            "safe_stats": {},
            "pii_sealed": {},
            "enriched": False,
            "error": str(exc),
        }


def _enrich_case_internal(
    alert_json: dict[str, Any],
    customer_id: str,
    now_utc: datetime,
) -> dict[str, Any]:

    # ── Step 1: Fetch customer KYC record ───────────────────────────────
    customer = get_customer(customer_id)
    if not customer:
        return {
            "safe_stats": {},
            "pii_sealed": {},
            "enriched": False,
            "error": f"Customer {customer_id} not found in database. "
                     "Ensure seed_data.py has been run and customer_id matches.",
        }

    # ── Step 2: Fetch all accounts for this customer ─────────────────────
    accounts = get_accounts_for_customer(customer_id)
    if not accounts:
        return {
            "safe_stats": {},
            "pii_sealed": {},
            "enriched": False,
            "error": f"No accounts found for customer {customer_id}.",
        }

    account_ids = [str(a["account_id"]) for a in accounts]

    # ── Step 3: Determine alert window boundaries ─────────────────────────
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

    # ── Step 4: Fetch 12-month transaction history ────────────────────────
    lookback_start = reference_end - timedelta(days=365)
    all_12m = get_transactions_in_range(account_ids, lookback_start, reference_end)

    # ── Step 5: Isolate alert-window transactions ─────────────────────────
    # These are the ONLY transactions that constitute the suspicious activity.
    # Transactions before alert_start or after reference_end are excluded.
    alert_window_txns = [
        t for t in all_12m
        if _safe_dt(t["timestamp"], now_utc) >= alert_start
        and _safe_dt(t["timestamp"], now_utc) <= reference_end
    ]

    # ── Step 6: Compute 12-month baseline from pre-alert history ─────────
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

    # ── Step 7: Compute deviation from baseline ───────────────────────────
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

    # ── Step 8: Counterparty intelligence ────────────────────────────────
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

    # ── Step 9: Build evidence buckets ───────────────────────────────────
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
        and t["txn_type"] in ("credit", "debit")
    ]

    high_velocity_txns = [str(t["txn_id"]) for t in alert_window_txns]

    # ── Step 10: Historical transaction count per month ───────────────────
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

    # ── Step 11: Build transaction details for PDF table ─────────────────
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

    # ── Step 12: Account tenure ───────────────────────────────────────────
    earliest_account = min(
        (a for a in accounts if a.get("opened_date")),
        key=lambda a: a["opened_date"],
        default=None,
    )
    account_opened_date = (
        earliest_account["opened_date"].strftime("%d %b %Y")
        if earliest_account and earliest_account.get("opened_date")
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

        # Date range as analyst-friendly strings (no ISO timestamps)
        "alert_date_range_start": _fmt_date(alert_start),
        "alert_date_range_end":   _fmt_date(reference_end),
    }

    pii_sealed: dict[str, Any] = {
        # These NEVER cross the PII boundary.
        # Used only by PDF export and sentence traceability.
        "customer_name":       str(customer["name"]),
        "occupation":          str(customer.get("occupation") or "N/A"),
        "risk_rating":         str(customer.get("risk_rating") or "N/A"),
        "account_opened_date": account_opened_date,

        # Real transaction IDs for sentence traceability
        "txn_buckets": {
            "high_velocity_txns": high_velocity_txns,
            "uae_transfers":      uae_transfers,
            "structuring_txns":   structuring_txns,
        },

        # Full transaction rows for PDF table
        "txn_table_rows": txn_table_rows,

        # Alert window as formatted strings for PDF display
        "alert_window_start_fmt": _fmt_date(alert_start),
        "alert_window_end_fmt":   _fmt_date(reference_end),
    }

    return {
        "safe_stats": safe_stats,
        "pii_sealed": pii_sealed,
        "enriched":   True,
        "error":      None,
    }