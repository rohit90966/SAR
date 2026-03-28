"""
seed_data.py — Seeds realistic KYC and transaction data into PostgreSQL.

Seeded customers:
  CUST_1001 — Arjun Malhotra (Student) — SUSPICIOUS — high-velocity UAE pass-through
  CUST_1002 — Priya Kapoor   (Salaried employee) — NORMAL — regular salary credits
  CUST_1003 — Rajan Mehta    (Retail business owner) — NORMAL — regular business activity
  CUST_1004 — Sunita Desai   (Retired) — NORMAL — small regular credits

Run:
    python scripts/seed_data.py

Safe to re-run — uses INSERT ... ON CONFLICT DO NOTHING for idempotency.
"""

from __future__ import annotations

import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Allow imports from project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/sar_audit",
)

# ── Seed constants ────────────────────────────────────────────────────────────
SEED_CUSTOMERS = [
    {
        "customer_id":    "CUST_1001",
        "name":           "Arjun Malhotra",
        "occupation":     "Student",
        "monthly_income": 15000.00,   # Student stipend
        "risk_rating":    "HIGH",
    },
    {
        "customer_id":    "CUST_1002",
        "name":           "Priya Kapoor",
        "occupation":     "Salaried employee",
        "monthly_income": 85000.00,
        "risk_rating":    "LOW",
    },
    {
        "customer_id":    "CUST_1003",
        "name":           "Rajan Mehta",
        "occupation":     "Retail business owner",
        "monthly_income": 150000.00,
        "risk_rating":    "MEDIUM",
    },
    {
        "customer_id":    "CUST_1004",
        "name":           "Sunita Desai",
        "occupation":     "Retired",
        "monthly_income": 25000.00,
        "risk_rating":    "LOW",
    },
]

SEED_ACCOUNTS = [
    {
        "account_id":   "ACC_1001_A",
        "customer_id":  "CUST_1001",
        "account_type": "current",
        "opened_date":  "2023-01-15",
    },
    {
        "account_id":   "ACC_1002_A",
        "customer_id":  "CUST_1002",
        "account_type": "savings",
        "opened_date":  "2019-06-01",
    },
    {
        "account_id":   "ACC_1003_A",
        "customer_id":  "CUST_1003",
        "account_type": "current",
        "opened_date":  "2018-03-20",
    },
    {
        "account_id":   "ACC_1004_A",
        "customer_id":  "CUST_1004",
        "account_type": "savings",
        "opened_date":  "2015-11-10",
    },
]


def _ts(days_ago: float, hour: int = 10, minute: int = 0) -> datetime:
    """Return a UTC datetime that many days before now."""
    base = datetime.now(timezone.utc).replace(
        hour=hour, minute=minute, second=0, microsecond=0
    )
    return base - timedelta(days=days_ago)


def _generate_transactions() -> list[dict]:
    """
    Generate realistic transaction history for all 4 customers.

    CUST_1001 — Suspicious pattern:
        - 11 months of normal low-volume activity (8-12 transactions/month)
        - Alert window (last 3 days): 57 high-velocity transactions
          - Mix of inbound credits from domestic sources
          - Outbound debits to UAE accounts (pass-through pattern)
          - Average individual amount INR 28,477 (below reporting threshold)

    CUST_1002 — Normal salaried pattern:
        - Monthly salary credit
        - 3-5 utility/grocery debits per month

    CUST_1003 — Normal business pattern:
        - Multiple credits from customers
        - Regular supplier payments

    CUST_1004 — Normal retired pattern:
        - Monthly pension credit
        - 2-3 small debits
    """
    txns: list[dict] = []
    txn_counter = 1

    def next_id() -> str:
        nonlocal txn_counter
        tid = f"TXN_{txn_counter:05d}"
        txn_counter += 1
        return tid

    rng = random.Random(42)  # Fixed seed for reproducibility

    # ── CUST_1001 — 11 months normal history ─────────────────────────────
    # Low-volume activity consistent with a student account
    domestic_sources_1001 = [
        "FAMILY_REMIT_001", "SCHOLARSHIP_FUND", "PART_TIME_SALARY",
        "FAMILY_REMIT_002", "TUITION_REFUND",
    ]
    domestic_expenses_1001 = [
        "HOSTEL_FEES", "CANTEEN_PAYMENT", "BOOKS_STORE",
        "TRANSPORT_CARD", "PHONE_RECHARGE",
    ]

    for month in range(11, 0, -1):
        # 2-3 credits per month (pocket money, part-time)
        for _ in range(rng.randint(2, 3)):
            days_ago = (month * 30) + rng.randint(1, 25)
            txns.append({
                "txn_id":      next_id(),
                "account_id":  "ACC_1001_A",
                "amount":      round(rng.uniform(5000, 18000), 2),
                "txn_type":    "credit",
                "country":     "INDIA",
                "timestamp":   _ts(days_ago, hour=rng.randint(9, 17)),
                "counterparty": rng.choice(domestic_sources_1001),
            })
        # 4-6 small debits per month
        for _ in range(rng.randint(4, 6)):
            days_ago = (month * 30) + rng.randint(1, 25)
            txns.append({
                "txn_id":      next_id(),
                "account_id":  "ACC_1001_A",
                "amount":      round(rng.uniform(500, 5000), 2),
                "txn_type":    "debit",
                "country":     "INDIA",
                "timestamp":   _ts(days_ago, hour=rng.randint(9, 20)),
                "counterparty": rng.choice(domestic_expenses_1001),
            })

    # ── CUST_1001 — Alert window (last 3 days) — SUSPICIOUS ──────────────
    # 57 transactions total:
    #   - 28 inbound credits from multiple new domestic counterparties
    #   - 29 outbound debits to UAE accounts
    # All individual amounts below INR 30,000 (structuring pattern)
    # New counterparties never seen in 11-month history

    suspicious_inbound_counterparties = [
        f"DOMESTIC_SOURCE_{i:03d}" for i in range(1, 29)
    ]
    uae_outbound_counterparties = [
        f"UAE_RECIPIENT_{i:03d}" for i in range(1, 30)
    ]

    # 28 credits over 3 days
    for idx, counterparty in enumerate(suspicious_inbound_counterparties):
        day_offset = rng.choice([2.5, 1.5, 0.5])  # spread over 3 days
        hour_offset = rng.randint(8, 20)
        txns.append({
            "txn_id":      next_id(),
            "account_id":  "ACC_1001_A",
            "amount":      round(rng.uniform(25000, 30000), 2),
            "txn_type":    "credit",
            "country":     "INDIA",
            "timestamp":   _ts(day_offset, hour=hour_offset, minute=rng.randint(0, 59)),
            "counterparty": counterparty,
        })

    # 29 outbound transfers to UAE (within hours of each inbound)
    for idx, counterparty in enumerate(uae_outbound_counterparties):
        day_offset = rng.choice([2.2, 1.2, 0.2])
        hour_offset = rng.randint(10, 22)
        txns.append({
            "txn_id":      next_id(),
            "account_id":  "ACC_1001_A",
            "amount":      round(rng.uniform(25000, 29500), 2),
            "txn_type":    "debit",
            "country":     "UAE",
            "timestamp":   _ts(day_offset, hour=hour_offset, minute=rng.randint(0, 59)),
            "counterparty": counterparty,
        })

    # ── CUST_1002 — Normal salaried employee ─────────────────────────────
    for month in range(12, 0, -1):
        # Monthly salary credit on the 1st
        txns.append({
            "txn_id":      next_id(),
            "account_id":  "ACC_1002_A",
            "amount":      85000.00,
            "txn_type":    "credit",
            "country":     "INDIA",
            "timestamp":   _ts((month * 30) - 2, hour=9),
            "counterparty": "EMPLOYER_PAYROLL",
        })
        # 3-5 regular debits
        for _ in range(rng.randint(3, 5)):
            days_ago = (month * 30) + rng.randint(5, 25)
            txns.append({
                "txn_id":      next_id(),
                "account_id":  "ACC_1002_A",
                "amount":      round(rng.uniform(2000, 25000), 2),
                "txn_type":    "debit",
                "country":     "INDIA",
                "timestamp":   _ts(days_ago, hour=rng.randint(10, 19)),
                "counterparty": rng.choice([
                    "ELECTRICITY_BOARD", "GROCERY_STORE",
                    "MOBILE_OPERATOR", "INSURANCE_PREMIUM", "RENT_PAYMENT",
                ]),
            })

    # ── CUST_1003 — Normal retail business ───────────────────────────────
    for month in range(12, 0, -1):
        # 8-12 customer payments received
        for _ in range(rng.randint(8, 12)):
            days_ago = (month * 30) + rng.randint(1, 28)
            txns.append({
                "txn_id":      next_id(),
                "account_id":  "ACC_1003_A",
                "amount":      round(rng.uniform(10000, 80000), 2),
                "txn_type":    "credit",
                "country":     "INDIA",
                "timestamp":   _ts(days_ago, hour=rng.randint(9, 18)),
                "counterparty": f"CUSTOMER_{rng.randint(1, 50):03d}",
            })
        # 4-6 supplier payments
        for _ in range(rng.randint(4, 6)):
            days_ago = (month * 30) + rng.randint(3, 28)
            txns.append({
                "txn_id":      next_id(),
                "account_id":  "ACC_1003_A",
                "amount":      round(rng.uniform(20000, 100000), 2),
                "txn_type":    "debit",
                "country":     "INDIA",
                "timestamp":   _ts(days_ago, hour=rng.randint(9, 17)),
                "counterparty": f"SUPPLIER_{rng.randint(1, 10):03d}",
            })

    # ── CUST_1004 — Normal retired ───────────────────────────────────────
    for month in range(12, 0, -1):
        # Monthly pension
        txns.append({
            "txn_id":      next_id(),
            "account_id":  "ACC_1004_A",
            "amount":      25000.00,
            "txn_type":    "credit",
            "country":     "INDIA",
            "timestamp":   _ts((month * 30) - 1, hour=10),
            "counterparty": "PENSION_FUND",
        })
        # 2-3 small utility payments
        for _ in range(rng.randint(2, 3)):
            days_ago = (month * 30) + rng.randint(5, 25)
            txns.append({
                "txn_id":      next_id(),
                "account_id":  "ACC_1004_A",
                "amount":      round(rng.uniform(500, 8000), 2),
                "txn_type":    "debit",
                "country":     "INDIA",
                "timestamp":   _ts(days_ago, hour=rng.randint(9, 15)),
                "counterparty": rng.choice([
                    "ELECTRICITY_BOARD", "WATER_BOARD",
                    "MEDICAL_PHARMACY", "GROCERY_STORE",
                ]),
            })

    return txns


def seed() -> None:
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    cursor = conn.cursor()

    print("Seeding customers...")
    execute_values(
        cursor,
        """
        INSERT INTO customers (customer_id, name, occupation, monthly_income, risk_rating)
        VALUES %s
        ON CONFLICT (customer_id) DO UPDATE SET
            name           = EXCLUDED.name,
            occupation     = EXCLUDED.occupation,
            monthly_income = EXCLUDED.monthly_income,
            risk_rating    = EXCLUDED.risk_rating
        """,
        [
            (c["customer_id"], c["name"], c["occupation"],
             c["monthly_income"], c["risk_rating"])
            for c in SEED_CUSTOMERS
        ],
    )
    print(f"  {len(SEED_CUSTOMERS)} customers seeded.")

    print("Seeding accounts...")
    execute_values(
        cursor,
        """
        INSERT INTO accounts (account_id, customer_id, account_type, opened_date)
        VALUES %s
        ON CONFLICT (account_id) DO NOTHING
        """,
        [
            (a["account_id"], a["customer_id"],
             a["account_type"], a["opened_date"])
            for a in SEED_ACCOUNTS
        ],
    )
    print(f"  {len(SEED_ACCOUNTS)} accounts seeded.")

    print("Generating transactions...")
    txns = _generate_transactions()
    print(f"  {len(txns)} transactions to seed...")

    execute_values(
        cursor,
        """
        INSERT INTO transactions
            (txn_id, account_id, amount, txn_type, country, timestamp, counterparty)
        VALUES %s
        ON CONFLICT (txn_id) DO NOTHING
        """,
        [
            (
                t["txn_id"],
                t["account_id"],
                t["amount"],
                t["txn_type"],
                t["country"],
                t["timestamp"],
                t.get("counterparty"),
            )
            for t in txns
        ],
        page_size=500,
    )
    print(f"  {len(txns)} transactions seeded.")

    conn.commit()
    cursor.close()
    conn.close()

    print("\nSeed complete.")
    print("Customer IDs: CUST_1001 (suspicious), CUST_1002, CUST_1003, CUST_1004")
    print("Use CUST_1001 in alert_case.json to trigger enrichment and AML rules.")


if __name__ == "__main__":
    seed()