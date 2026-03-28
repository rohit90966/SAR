from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator
import json
import os

import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json, RealDictCursor


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def get_database_url() -> str:
    return os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/sar_audit",
    )


@contextmanager
def get_connection() -> Iterator[Any]:
    connection = psycopg2.connect(get_database_url())
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    ddl = """
    CREATE TABLE IF NOT EXISTS cases (
        case_id              UUID         PRIMARY KEY,
        alert_id             TEXT         NOT NULL,
        status               TEXT         NOT NULL,
        risk_score           DOUBLE PRECISION,
        risk_level           TEXT,
        alert_payload        JSONB        NOT NULL,
        masked_alert_payload JSONB        NOT NULL,
        evidence_pack        JSONB,
        retrieval_payload    JSONB,
        prompt_payload       JSONB,
        validation_payload   JSONB,
        final_sar            JSONB,
        analyst_review       JSONB,
        replay_payload       JSONB,
        enrichment_payload   JSONB,
        created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_cases_status      ON cases(status);
    CREATE INDEX IF NOT EXISTS idx_cases_risk_score  ON cases(risk_score DESC NULLS LAST);
    CREATE INDEX IF NOT EXISTS idx_cases_updated_at  ON cases(updated_at DESC);

    CREATE TABLE IF NOT EXISTS audit_events (
        event_id      BIGSERIAL    PRIMARY KEY,
        case_id       UUID         NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
        event_type    TEXT         NOT NULL,
        event_payload JSONB        NOT NULL,
        created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_audit_case_id ON audit_events(case_id, created_at);

    CREATE TABLE IF NOT EXISTS customers (
        customer_id    TEXT         PRIMARY KEY,
        name           TEXT         NOT NULL,
        occupation     TEXT,
        monthly_income NUMERIC(15,2),
        risk_rating    TEXT         DEFAULT 'LOW',
        created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_customers_risk ON customers(risk_rating);

    CREATE TABLE IF NOT EXISTS accounts (
        account_id    TEXT         PRIMARY KEY,
        customer_id   TEXT         NOT NULL REFERENCES customers(customer_id) ON DELETE CASCADE,
        account_type  TEXT         NOT NULL,
        opened_date   DATE,
        created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_accounts_customer ON accounts(customer_id);

    CREATE TABLE IF NOT EXISTS transactions (
        txn_id       TEXT         PRIMARY KEY,
        account_id   TEXT         NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        amount       NUMERIC(15,2) NOT NULL,
        txn_type     TEXT         NOT NULL CHECK (txn_type IN ('credit', 'debit')),
        country      TEXT         DEFAULT 'INDIA',
        timestamp    TIMESTAMPTZ  NOT NULL,
        counterparty TEXT,
        created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_txn_account_id  ON transactions(account_id);
    CREATE INDEX IF NOT EXISTS idx_txn_timestamp   ON transactions(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_txn_country     ON transactions(country);
    CREATE INDEX IF NOT EXISTS idx_txn_type        ON transactions(txn_type);

    -- ── QUARANTINE QUEUE ─────────────────────────────────────────────────
    -- Holds alerts that arrived before their regulatory framework
    -- was configured. Released automatically when regulation is activated.
    CREATE TABLE IF NOT EXISTS quarantine_queue (
        quarantine_id   TEXT         PRIMARY KEY,
        alert_payload   JSONB        NOT NULL,
        asset_type      TEXT         NOT NULL,
        reason          TEXT         NOT NULL,
        missing_items   JSONB,
        quarantined_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        resolved_at     TIMESTAMPTZ,
        status          TEXT         NOT NULL DEFAULT 'WAITING'
    );

    CREATE INDEX IF NOT EXISTS idx_quarantine_asset_type ON quarantine_queue(asset_type, status);
    CREATE INDEX IF NOT EXISTS idx_quarantine_status     ON quarantine_queue(status);

    -- ── REGULATION RULES STAGING ─────────────────────────────────────────
    -- Holds LLM-proposed rules before compliance officer approves
    -- and before they are written to rules.yaml.
    -- status: PROPOSED -> APPROVED -> PROMOTED | REJECTED
    CREATE TABLE IF NOT EXISTS regulation_staging (
        staging_id       TEXT         PRIMARY KEY,
        asset_type       TEXT         NOT NULL,
        source_file      TEXT         NOT NULL,
        proposed_rules   JSONB        NOT NULL,
        dry_run_result   JSONB,
        citation_checks  JSONB,
        proposed_by      TEXT         NOT NULL DEFAULT 'llm',
        reviewed_by      TEXT,
        status           TEXT         NOT NULL DEFAULT 'PROPOSED',
        proposed_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        reviewed_at      TIMESTAMPTZ,
        promoted_at      TIMESTAMPTZ,
        rejection_reason TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_staging_asset_type ON regulation_staging(asset_type, status);
    CREATE INDEX IF NOT EXISTS idx_staging_status     ON regulation_staging(status);

    CREATE TABLE IF NOT EXISTS alert_dispositions (
        case_id          TEXT         PRIMARY KEY,
        rule_ids         JSONB        NOT NULL,
        customer_profile TEXT         NOT NULL,
        disposition      TEXT         NOT NULL CHECK (disposition IN ('TRUE_POSITIVE','FALSE_POSITIVE')),
        disposed_by      TEXT         NOT NULL,
        disposed_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_dispositions_profile_rules
        ON alert_dispositions(customer_profile, rule_ids);
    CREATE INDEX IF NOT EXISTS idx_dispositions_disposed_at
        ON alert_dispositions(disposed_at DESC);

    -- ── CUSTOMER SAR HISTORY ─────────────────────────────────────────────────
    -- Records every approved SAR against a customer with full timeline.
    -- Written by submit_review() when analyst decision is APPROVE.
    -- Read by enrich_case() to build customer background block.
    CREATE TABLE IF NOT EXISTS customer_sar_history (
        history_id          BIGSERIAL     PRIMARY KEY,
        customer_id         TEXT          NOT NULL,
        case_id             TEXT          NOT NULL,
        alert_id            TEXT          NOT NULL,
        alert_type          TEXT          NOT NULL,
        risk_level          TEXT          NOT NULL,
        risk_score          DOUBLE PRECISION,
        total_amount        NUMERIC(15,2),
        destination_country TEXT,
        approved_by         TEXT          NOT NULL,
        approved_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
        rules_triggered     JSONB,
        narrative_summary   TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_sar_history_customer
        ON customer_sar_history(customer_id, approved_at DESC);

    CREATE INDEX IF NOT EXISTS idx_sar_history_case
        ON customer_sar_history(case_id);
    """

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(ddl)
            cursor.execute(
                "ALTER TABLE IF EXISTS cases ADD COLUMN IF NOT EXISTS enrichment_payload JSONB"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS cases "
                "ADD COLUMN IF NOT EXISTS false_alert_score JSONB"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS regulation_staging "
                "ADD COLUMN IF NOT EXISTS regulation_list JSONB"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS regulation_staging "
                "ADD COLUMN IF NOT EXISTS conclusion_regulation TEXT"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS regulation_staging "
                "ADD COLUMN IF NOT EXISTS additional_prompt_context TEXT"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS regulation_staging "
                "ADD COLUMN IF NOT EXISTS document_text TEXT"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS regulation_staging "
                "ADD COLUMN IF NOT EXISTS threshold_changes JSONB"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS regulation_staging "
                "ADD COLUMN IF NOT EXISTS gap_report JSONB"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS regulation_staging "
                "ADD COLUMN IF NOT EXISTS rule_types_detected JSONB"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS regulation_staging "
                "ADD COLUMN IF NOT EXISTS extracted_params JSONB"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS regulation_staging "
                "ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS regulation_staging "
                "ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ"
            )
            cursor.execute(
                "UPDATE regulation_staging SET created_at = COALESCE(created_at, proposed_at, NOW())"
            )
            cursor.execute(
                "UPDATE regulation_staging SET updated_at = COALESCE(updated_at, reviewed_at, promoted_at, proposed_at, NOW())"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS quarantine_queue "
                "ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS quarantine_queue "
                "ADD COLUMN IF NOT EXISTS released_at TIMESTAMPTZ"
            )
            cursor.execute(
                "UPDATE quarantine_queue SET created_at = COALESCE(created_at, quarantined_at, NOW())"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS customers "
                "ADD COLUMN IF NOT EXISTS relationship_since DATE"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS customers "
                "ADD COLUMN IF NOT EXISTS relationship_type TEXT DEFAULT 'STANDARD'"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS customers "
                "ADD COLUMN IF NOT EXISTS pep_flag BOOLEAN DEFAULT FALSE"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS customers "
                "ADD COLUMN IF NOT EXISTS adverse_media_flag BOOLEAN DEFAULT FALSE"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS customers "
                "ADD COLUMN IF NOT EXISTS nationality TEXT"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS customers "
                "ADD COLUMN IF NOT EXISTS date_of_birth DATE"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS customers "
                "ADD COLUMN IF NOT EXISTS kyc_last_reviewed DATE"
            )
            cursor.execute(
                "ALTER TABLE IF EXISTS customers "
                "ADD COLUMN IF NOT EXISTS kyc_review_due DATE"
            )
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS customer_sar_history ("
                "    history_id          BIGSERIAL     PRIMARY KEY,"
                "    customer_id         TEXT          NOT NULL,"
                "    case_id             TEXT          NOT NULL,"
                "    alert_id            TEXT          NOT NULL,"
                "    alert_type          TEXT          NOT NULL,"
                "    risk_level          TEXT          NOT NULL,"
                "    risk_score          DOUBLE PRECISION,"
                "    total_amount        NUMERIC(15,2),"
                "    destination_country TEXT,"
                "    approved_by         TEXT          NOT NULL,"
                "    approved_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),"
                "    rules_triggered     JSONB,"
                "    narrative_summary   TEXT"
                ")"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_sar_history_customer "
                "ON customer_sar_history(customer_id, approved_at DESC)"
            )


# ════════════════════════════════════════════════════════
# CASE CRUD
# ════════════════════════════════════════════════════════

def create_case(
    case_id: str,
    alert_payload: dict[str, Any],
    masked_alert_payload: dict[str, Any],
) -> None:
    query = """
    INSERT INTO cases (
        case_id, alert_id, status,
        alert_payload, masked_alert_payload,
        created_at, updated_at
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s)
    """
    now = utc_now()
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, (
                case_id,
                alert_payload["alert_id"],
                "INGESTED",
                Json(alert_payload),
                Json(masked_alert_payload),
                now,
                now,
            ))


def update_case(case_id: str, **fields: Any) -> None:
    if not fields:
        return

    assignments = []
    values = []
    fields["updated_at"] = utc_now()

    for key, value in fields.items():
        assignments.append(
            sql.SQL("{} = %s").format(sql.Identifier(key))
        )
        values.append(Json(value) if isinstance(value, (dict, list)) else value)

    statement = sql.SQL("UPDATE cases SET {} WHERE case_id = %s").format(
        sql.SQL(", ").join(assignments)
    )
    values.append(case_id)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(statement, values)


def append_audit_event(
    case_id: str,
    event_type: str,
    event_payload: dict[str, Any],
) -> None:
    query = """
    INSERT INTO audit_events (case_id, event_type, event_payload)
    VALUES (%s, %s, %s)
    """
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, (case_id, event_type, Json(event_payload)))


def get_case(case_id: str) -> dict[str, Any] | None:
    query = "SELECT * FROM cases WHERE case_id = %s"
    with get_connection() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, (case_id,))
            return cursor.fetchone()


def list_cases() -> list[dict[str, Any]]:
    query = """
    SELECT
        case_id, alert_id, status, risk_score, risk_level,
        final_sar, analyst_review, created_at, updated_at
    FROM cases
    ORDER BY risk_score DESC NULLS LAST, updated_at DESC
    """
    with get_connection() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query)
            return cursor.fetchall()


def get_audit_events(case_id: str) -> list[dict[str, Any]]:
    query = """
    SELECT event_id, case_id, event_type, event_payload, created_at
    FROM audit_events
    WHERE case_id = %s
    ORDER BY created_at, event_id
    """
    with get_connection() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, (case_id,))
            return cursor.fetchall()


# ════════════════════════════════════════════════════════
# QUARANTINE QUEUE
# ════════════════════════════════════════════════════════

def quarantine_alert(
    quarantine_id: str,
    alert_payload: dict[str, Any],
    asset_type: str,
    reason: str,
    missing_items: list[str] | None = None,
) -> None:
    query = """
    INSERT INTO quarantine_queue
        (quarantine_id, asset_type, alert_payload, reason, missing_items, status, created_at)
    VALUES (%s, %s, %s, %s, %s, 'WAITING', %s)
    """
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, (
                quarantine_id,
                asset_type,
                Json(alert_payload),
                reason,
                Json(missing_items or []),
                utc_now(),
            ))


def get_quarantined_alerts(asset_type: str) -> list[dict[str, Any]]:
    query = """
    SELECT quarantine_id, alert_payload
    FROM quarantine_queue
    WHERE asset_type = %s AND status IN ('PENDING', 'WAITING')
    ORDER BY created_at ASC
    """
    with get_connection() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, (asset_type,))
            return cursor.fetchall()


def release_quarantined_alerts(asset_type: str) -> list[dict[str, Any]]:
    """
    Marks all PENDING/WAITING quarantine records for this asset_type as RELEASED.
    Returns the alert payloads so the caller can reprocess them.
    """
    with get_connection() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT quarantine_id, alert_payload
                FROM quarantine_queue
                WHERE asset_type = %s AND status IN ('PENDING', 'WAITING')
                ORDER BY created_at ASC
            """, (asset_type,))
            rows = cursor.fetchall()

            cursor.execute("""
                UPDATE quarantine_queue
                SET status = 'RELEASED', released_at = NOW()
                WHERE asset_type = %s AND status IN ('PENDING', 'WAITING')
            """, (asset_type,))

    return rows


def list_quarantine_queue(
    asset_type: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    conditions = []
    params: list[Any] = []
    if asset_type:
        conditions.append("asset_type = %s")
        params.append(asset_type)
    if status:
        conditions.append("status = %s")
        params.append(status)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    query = f"""
    SELECT quarantine_id, asset_type, reason, status, created_at, released_at,
           alert_payload->>'alert_id' AS alert_id,
           alert_payload->>'alert_type' AS alert_type
    FROM quarantine_queue
    {where}
    ORDER BY created_at DESC
    """
    with get_connection() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()


# ════════════════════════════════════════════════════════
# REGULATION STAGING
# ════════════════════════════════════════════════════════

def create_staging_entry(
    staging_id: str,
    asset_type: str,
    source_file: str,
    proposed_rules: list[dict[str, Any]],
    dry_run_result: dict[str, Any],
    citation_checks: dict[str, Any],
    regulation_list: list[str] | None = None,
    conclusion_regulation: str = "",
    additional_prompt_context: str = "",
    document_text: str = "",
    threshold_changes: list[dict[str, Any]] | None = None,
    gap_report: dict[str, Any] | None = None,
    rule_types_detected: list[str] | None = None,
    extracted_params: dict[str, Any] | None = None,
) -> None:
    query = """
    INSERT INTO regulation_staging
        (staging_id, asset_type, source_file, proposed_rules,
         dry_run_result, citation_checks, regulation_list,
            conclusion_regulation, additional_prompt_context, document_text,
            threshold_changes, gap_report, rule_types_detected, extracted_params,
         status, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'PROPOSED', %s, %s)
    """
    now = utc_now()
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, (
                staging_id,
                asset_type,
                source_file,
                Json(proposed_rules),
                Json(dry_run_result),
                Json(citation_checks),
                Json(regulation_list or []),
                conclusion_regulation,
                additional_prompt_context,
                document_text,
                Json(threshold_changes or []),
                Json(gap_report) if gap_report else None,
                Json(rule_types_detected or []),
                Json(extracted_params or {}),
                now,
                now,
            ))


def get_staging_entry(staging_id: str) -> dict[str, Any] | None:
    query = "SELECT * FROM regulation_staging WHERE staging_id = %s"
    with get_connection() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, (staging_id,))
            return cursor.fetchone()


def update_staging_status(
    staging_id: str,
    status: str,
    reviewed_by: str,
    rejection_reason: str | None = None,
) -> None:
    query = """
    UPDATE regulation_staging
    SET status = %s,
        reviewed_by = %s,
        rejection_reason = %s,
        reviewed_at = %s,
        updated_at = %s
    WHERE staging_id = %s
    """
    now = utc_now()
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, (status, reviewed_by, rejection_reason, now, now, staging_id))


def promote_staging_entry(staging_id: str) -> None:
    """Mark a staging entry as PROMOTED (rules written to rules.yaml)."""
    query = """
    UPDATE regulation_staging
    SET status = 'PROMOTED', updated_at = %s
    WHERE staging_id = %s
    """
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, (utc_now(), staging_id))


def list_staging_entries(status: str | None = None) -> list[dict[str, Any]]:
    if status:
        query = """
        SELECT staging_id, asset_type, source_file, status,
             created_at AS proposed_at, reviewed_at, updated_at, reviewed_by,
         jsonb_array_length(proposed_rules) AS rule_count,
         threshold_changes, rule_types_detected, extracted_params, gap_report
        FROM regulation_staging
        WHERE status = %s
     ORDER BY created_at DESC
        """
        params = (status,)
    else:
        query = """
        SELECT staging_id, asset_type, source_file, status,
             created_at AS proposed_at, reviewed_at, updated_at, reviewed_by,
         jsonb_array_length(proposed_rules) AS rule_count,
         threshold_changes, rule_types_detected, extracted_params, gap_report
        FROM regulation_staging
     ORDER BY created_at DESC
        """
        params = ()

    with get_connection() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()


# ════════════════════════════════════════════════════════
# ENRICHMENT QUERIES
# ════════════════════════════════════════════════════════

def get_customer(customer_id: str) -> dict[str, Any] | None:
    query = "SELECT * FROM customers WHERE customer_id = %s"
    with get_connection() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, (customer_id,))
            return cursor.fetchone()


def get_accounts_for_customer(customer_id: str) -> list[dict[str, Any]]:
    query = """
    SELECT * FROM accounts
    WHERE customer_id = %s
    ORDER BY opened_date ASC NULLS LAST
    """
    with get_connection() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, (customer_id,))
            return cursor.fetchall()


def get_transactions_in_range(
    account_ids: list[str],
    start_ts: datetime,
    end_ts: datetime,
) -> list[dict[str, Any]]:
    if not account_ids:
        return []

    query = """
    SELECT *
    FROM transactions
    WHERE account_id = ANY(%s)
      AND timestamp >= %s
      AND timestamp <= %s
    ORDER BY timestamp ASC
    """
    with get_connection() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, (account_ids, start_ts, end_ts))
            return cursor.fetchall()


def get_latest_transaction_timestamp(account_ids: list[str]) -> datetime | None:
    if not account_ids:
        return None

    query = """
    SELECT MAX(timestamp) AS latest
    FROM transactions
    WHERE account_id = ANY(%s)
    """
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, (account_ids,))
            row = cursor.fetchone()
            return row[0] if row and row[0] else None


def record_alert_disposition(
    case_id: str,
    rule_ids: list[str],
    customer_profile: str,
    disposition: str,
    disposed_by: str,
) -> None:
    """
    Records whether an analyst marked a case TRUE_POSITIVE or FALSE_POSITIVE.
    Called from submit_review() in app.py every time an analyst approves or rejects.
    Also called automatically when the false alert filter auto-closes a case.
    This builds the historical feedback loop that Signal 6 uses.
    ON CONFLICT means if the same case is reviewed twice, latest decision wins.
    """
    query = """
    INSERT INTO alert_dispositions
        (case_id, rule_ids, customer_profile, disposition, disposed_by, disposed_at)
    VALUES (%s, %s, %s, %s, %s, NOW())
    ON CONFLICT (case_id) DO UPDATE
        SET disposition = EXCLUDED.disposition,
            disposed_by = EXCLUDED.disposed_by,
            disposed_at = NOW()
    """
    normalized_profile = str(customer_profile or "").strip() or "UNKNOWN"
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (
                case_id,
                Json(sorted(rule_ids)),
                normalized_profile,
                disposition,
                disposed_by,
            ))


def get_historical_fp_rate(
    rule_ids: list[str],
    customer_profile: str,
    lookback_days: int = 90,
) -> float:
    """
    Returns the fraction of past alerts with this exact rule combination
    and customer profile that were closed as FALSE_POSITIVE.

    Returns 0.5 (neutral - not enough data) if fewer than 10 historical
    samples exist. This prevents the signal from dominating early on
    when there is insufficient data to trust it.

    rule_ids must be sorted before passing so JSON comparison works.
    lookback_days=90 means only last 90 days of decisions are used -
    older decisions may reflect old thresholds and should not influence
    current scoring.
    """
    query = """
    SELECT
        COUNT(*) FILTER (WHERE disposition = 'FALSE_POSITIVE') AS fp_count,
        COUNT(*) AS total_count
    FROM alert_dispositions
    WHERE customer_profile = %s
      AND rule_ids = %s
      AND disposed_at >= NOW() - make_interval(days => %s)
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (
                customer_profile,
                Json(sorted(rule_ids)),
                lookback_days,
            ))
            row = cur.fetchone()
            if not row or not row[1] or int(row[1]) < 10:
                return 0.5
            return round(int(row[0]) / int(row[1]), 3)


# ════════════════════════════════════════════════════════
# CUSTOMER SAR HISTORY
# ════════════════════════════════════════════════════════

def record_customer_sar_approval(
    customer_id: str,
    case_id: str,
    alert_id: str,
    alert_type: str,
    risk_level: str,
    risk_score: float,
    total_amount: float,
    destination_country: str,
    approved_by: str,
    rules_triggered: list[str],
    narrative_summary: str,
) -> None:
    """
    Called from submit_review() when analyst approves a SAR.
    Builds the customer SAR history timeline.
    """
    query = """
    INSERT INTO customer_sar_history (
        customer_id, case_id, alert_id, alert_type,
        risk_level, risk_score, total_amount,
        destination_country, approved_by,
        rules_triggered, narrative_summary
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (
                customer_id,
                case_id,
                alert_id,
                alert_type,
                risk_level,
                float(risk_score or 0),
                float(total_amount or 0),
                destination_country,
                approved_by,
                Json(rules_triggered or []),
                narrative_summary,
            ))


def get_customer_sar_history(
    customer_id: str,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """
    Returns approved SAR history for a customer ordered newest first.
    Used by enrich_case() to build customer background block.
    """
    query = """
    SELECT
        history_id,
        case_id,
        alert_id,
        alert_type,
        risk_level,
        risk_score,
        total_amount,
        destination_country,
        approved_by,
        approved_at,
        rules_triggered,
        narrative_summary
    FROM customer_sar_history
    WHERE customer_id = %s
    ORDER BY approved_at DESC
    LIMIT %s
    """
    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, (customer_id, limit))
            return cur.fetchall()


def get_customer_sar_summary(customer_id: str) -> dict[str, Any]:
    """
    Returns aggregate SAR statistics for a customer.
    Used in customer background block of SAR narrative.
    """
    query = """
    SELECT
        COUNT(*)                                    AS total_sars_filed,
        MAX(approved_at)                            AS most_recent_sar_date,
        MIN(approved_at)                            AS first_sar_date,
        ROUND(AVG(risk_score)::numeric, 3)          AS avg_risk_score,
        SUM(total_amount)                           AS total_suspicious_amount,
        COUNT(*) FILTER (WHERE risk_level = 'HIGH') AS high_risk_count,
        array_agg(DISTINCT alert_type)              AS alert_types_seen,
        array_agg(DISTINCT destination_country)
            FILTER (WHERE destination_country IS NOT NULL) AS countries_involved
    FROM customer_sar_history
    WHERE customer_id = %s
    """
    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, (customer_id,))
            row = cur.fetchone()
            if not row or not row["total_sars_filed"]:
                return {
                    "total_sars_filed": 0,
                    "most_recent_sar_date": None,
                    "first_sar_date": None,
                    "avg_risk_score": None,
                    "total_suspicious_amount": 0,
                    "high_risk_count": 0,
                    "alert_types_seen": [],
                    "countries_involved": [],
                    "is_repeat_sar_customer": False,
                }
            return {
                **dict(row),
                "is_repeat_sar_customer": int(row["total_sars_filed"]) > 1,
            }


def get_full_customer_kyc(customer_id: str) -> dict[str, Any] | None:
    """
    Fetches all KYC fields including new relationship and flag fields.
    Replaces the old get_customer() call in enrichment.
    """
    query = """
    SELECT
        c.customer_id,
        c.name,
        c.occupation,
        c.monthly_income,
        c.risk_rating,
        c.relationship_since,
        c.relationship_type,
        c.pep_flag,
        c.adverse_media_flag,
        c.nationality,
        c.date_of_birth,
        c.kyc_last_reviewed,
        c.kyc_review_due,
        c.created_at,
        COUNT(a.account_id) AS total_accounts,
        MIN(a.opened_date) AS earliest_account_date,
        array_agg(a.account_type) FILTER (WHERE a.account_type IS NOT NULL) AS account_types
    FROM customers c
    LEFT JOIN accounts a ON a.customer_id = c.customer_id
    WHERE c.customer_id = %s
    GROUP BY c.customer_id, c.name, c.occupation, c.monthly_income,
             c.risk_rating, c.relationship_since, c.relationship_type,
             c.pep_flag, c.adverse_media_flag, c.nationality,
             c.date_of_birth, c.kyc_last_reviewed, c.kyc_review_due,
             c.created_at
    """
    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, (customer_id,))
            return cur.fetchone()