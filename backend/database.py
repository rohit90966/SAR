from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator
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
    """
    Creates all tables on startup if they do not exist.

    Tables:
      cases          — SAR case records with full pipeline payloads
      audit_events   — Immutable append-only audit trail per case
      customers      — KYC master records (enrichment source)
      accounts       — Account records linked to customers
      transactions   — Individual transaction records for enrichment
    """
    ddl = """
    -- ── SAR CASE MANAGEMENT ─────────────────────────────────────────────
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

    -- ── AUDIT TRAIL ──────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS audit_events (
        event_id      BIGSERIAL    PRIMARY KEY,
        case_id       UUID         NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
        event_type    TEXT         NOT NULL,
        event_payload JSONB        NOT NULL,
        created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_audit_case_id ON audit_events(case_id, created_at);

    -- ── KYC ENRICHMENT — CUSTOMERS ───────────────────────────────────────
    -- Stores customer master data used for enrichment.
    -- customer_id matches the alert payload customer_id field.
    -- monthly_income is the declared income from KYC documentation.
    -- risk_rating is the institution's internal customer risk classification.
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

    -- ── KYC ENRICHMENT — ACCOUNTS ────────────────────────────────────────
    -- One customer can have multiple accounts.
    -- account_type: Savings / Current / Fixed Deposit etc.
    -- opened_date: used for account tenure computation.
    CREATE TABLE IF NOT EXISTS accounts (
        account_id    TEXT         PRIMARY KEY,
        customer_id   TEXT         NOT NULL REFERENCES customers(customer_id) ON DELETE CASCADE,
        account_type  TEXT         NOT NULL,
        opened_date   DATE,
        created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_accounts_customer ON accounts(customer_id);

    -- ── KYC ENRICHMENT — TRANSACTIONS ────────────────────────────────────
    -- Individual transaction records used for:
    --   - computing 12-month deposit baseline
    --   - identifying alert-window transactions
    --   - counterparty intelligence (new vs prior relationships)
    --   - building evidence buckets (UAE transfers, structuring, velocity)
    --
    -- counterparty: the name or account reference of the other party.
    --   For credits: the sender.
    --   For debits: the recipient.
    -- country: destination for debits, origin for credits.
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
    """

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(ddl)
            # Backward-compatible migration for older databases created before
            # enrichment payload support was added.
            cursor.execute(
                "ALTER TABLE IF EXISTS cases ADD COLUMN IF NOT EXISTS enrichment_payload JSONB"
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
# ENRICHMENT QUERIES
# These are called by enrichment.py only.
# Raw psycopg2 queries — no ORM dependency.
# ════════════════════════════════════════════════════════

def get_customer(customer_id: str) -> dict[str, Any] | None:
    """Fetch KYC master record for a customer."""
    query = "SELECT * FROM customers WHERE customer_id = %s"
    with get_connection() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, (customer_id,))
            return cursor.fetchone()


def get_accounts_for_customer(customer_id: str) -> list[dict[str, Any]]:
    """Fetch all accounts belonging to a customer."""
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
    """
    Fetch all transactions for the given accounts within the time range.
    Used for:
      - alert window transactions (short range — 3 days)
      - 12-month baseline transactions (long range — 365 days)
    """
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
    """
    Returns the timestamp of the most recent transaction across all accounts.
    Used as fallback anchor when alert_window_end is not provided.
    """
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