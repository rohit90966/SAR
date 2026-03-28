from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Transactions(BaseModel):
    transaction_count: int
    total_amount: float
    time_window_days: int
    destination_country: str | None = None
    reporting_threshold: float | None = None
    min_transaction_amount: float | None = None
    max_transaction_amount: float | None = None


class CustomerFinancials(BaseModel):
    declared_monthly_income: float | None = None
    avg_monthly_deposits_12m: float | None = None
    historical_baseline_txn_count: int | None = None


class AlertPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    alert_id: str
    customer_id: str
    alert_type: str
    asset_type: str = "FIAT_WIRE"
    pattern: str
    transactions: Transactions
    customer_name: str | None = None
    account_type: str | None = None
    customer_profile: str | None = None
    customer_financials: CustomerFinancials | None = None


class ReviewRequest(BaseModel):
    analyst_id: str = Field(min_length=2)
    decision: Literal["APPROVE", "REJECT"]
    comment: str = Field(min_length=10)
    edited_narrative: str | None = None


class ReplayResponse(BaseModel):
    replayed: bool
    replayed_at: str
    replay_matches_original: bool | None = None
    replayed_narrative: str | None = None
    original_narrative: str | None = None
    reason: str | None = None
    raw_response: dict[str, Any] | None = None


# ── Regulation authoring schemas ──────────────────────────────────────────────

class RegulationUploadRequest(BaseModel):
    """
    Payload for POST /regulations/upload.

    Supports two modes:
      1) document_text  - plain text already extracted by client
      2) file_bytes_b64 - base64 encoded PDF/DOCX bytes
    """
    document_text: str | None = Field(
        default=None,
        description="Full text of the regulation document (plain text mode).",
    )
    file_bytes_b64: str | None = Field(
        default=None,
        description="Base64-encoded PDF or DOCX file bytes.",
    )
    source_filename: str = Field(
        min_length=3,
        description="Original filename of the uploaded document, for audit trail.",
    )
    asset_type: str = Field(
        default="FIAT_WIRE",
        description="Asset type this regulation governs: FIAT_WIRE or CRYPTO_VDA.",
    )

    @model_validator(mode="after")
    def check_text_or_bytes(self) -> "RegulationUploadRequest":
        if not self.document_text and not self.file_bytes_b64:
            raise ValueError("Either document_text or file_bytes_b64 must be provided.")
        return self


class StagingReviewRequest(BaseModel):
    """Payload for POST /regulations/staging/{staging_id}/review"""
    decision: Literal["APPROVE", "REJECT"]
    rejection_reason: str | None = Field(
        default=None,
        description="Required when decision is REJECT. Explain why rules were rejected.",
    )
    approved_changes: list[str] | None = Field(
        default=None,
        description=(
            "Optional list of threshold keys to approve. "
            "If None, all staged threshold changes are applied."
        ),
    )

    @model_validator(mode='after')
    def check_rejection_reason(self) -> 'StagingReviewRequest':
        if self.decision == "REJECT" and not self.rejection_reason:
            raise ValueError("rejection_reason is required when decision is REJECT.")
        if self.decision == "APPROVE":
            self.rejection_reason = None
        return self