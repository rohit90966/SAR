from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


# ════════════════════════════════════════════════════════
# ALERT PAYLOAD SCHEMAS
# customer_financials is now OPTIONAL — enrichment.py
# fetches it from PostgreSQL using customer_id.
# If the caller provides it manually it is used as-is
# (backward-compatible with existing alert_case.json files).
# ════════════════════════════════════════════════════════

class Transactions(BaseModel):
    transaction_count: int
    total_amount: float
    time_window_days: int
    destination_country: str | None = None
    reporting_threshold: float | None = None
    min_transaction_amount: float | None = None
    max_transaction_amount: float | None = None


class CustomerFinancials(BaseModel):
    """
    Populated by enrichment.py from PostgreSQL at case creation time.
    Can also be provided directly in the alert payload for backward
    compatibility or when enrichment data is unavailable.
    """
    declared_monthly_income: float | None = None
    avg_monthly_deposits_12m: float | None = None
    historical_baseline_txn_count: int | None = None
    deviation_from_baseline_pct: float | None = None


class AlertPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    alert_id: str
    customer_id: str
    customer_name: str
    account_type: str
    customer_profile: str
    alert_type: str
    transactions: Transactions
    pattern: str

    # Populated by enrichment at runtime — not required in alert JSON
    customer_financials: CustomerFinancials | None = None

    # TMS detection window — prevents late-filing date drift in enrichment
    # If not provided, enrichment falls back to latest DB transaction as anchor
    alert_window_start: str | None = None
    alert_window_end: str | None = None


# ════════════════════════════════════════════════════════
# ANALYST REVIEW
# ════════════════════════════════════════════════════════

class ReviewRequest(BaseModel):
    analyst_id: str = Field(min_length=2)
    decision: Literal["APPROVE", "REJECT"]
    comment: str = Field(min_length=10)
    edited_narrative: str | None = None


# ════════════════════════════════════════════════════════
# REPLAY RESPONSE
# ════════════════════════════════════════════════════════

class ReplayResponse(BaseModel):
    replayed: bool
    replayed_at: str
    replay_matches_original: bool | None = None
    replayed_narrative: str | None = None
    original_narrative: str | None = None
    reason: str | None = None
    raw_response: dict[str, Any] | None = None