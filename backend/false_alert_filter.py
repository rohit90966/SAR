from __future__ import annotations

"""
false_alert_filter.py - Pre-pipeline false alert scoring.

This module runs AFTER evaluate_rules() returns evidence_blocks
but BEFORE enrich_case() and service.process_alert() are called.

It scores each alert across 6 signals and returns one of three verdicts:
    LIKELY_FALSE  - auto-close, no enrichment, no LLM, no ChromaDB
    BORDERLINE    - send to analyst triage queue, no LLM runs
    LIKELY_TRUE   - continue to full pipeline

Architecture note:
    This module deliberately uses only:
    - evidence_blocks (already computed by evaluate_rules, free)
    - load_rule_config() (lru_cache, free after first call)
    - get_customer() (single DB query, lightweight)
    - get_historical_fp_rate() (single DB query, lightweight)

    It does NOT call:
    - enrich_case() - that is what we are trying to avoid for false alerts
    - ChromaDB - expensive vector retrieval
    - Ollama - LLM generation

The 6 signals:

    Signal 1 - Rule count and type quality
        Threshold-based rules (AML-001 to AML-007, AML-013) require
        measured numeric values to breach. They are strong evidence.
        Keyword-only rules (AML-008 to AML-012) fire because someone
        typed a word in the pattern field. They are weak evidence.
        If only keyword rules fired, it is almost certainly false.

    Signal 2 - Average rule confidence
        The rule engine already computes confidence per rule.
        A barely-breaching alert gets low confidence via scaled_cap mode.
        Low average confidence across all fired rules = likely false.

    Signal 3 - KYC risk rating
        Fetched from the customers table via get_customer().
        A LOW risk customer with clean history triggering one velocity
        rule is almost certainly a false positive.

    Signal 4 - Profile-amount consistency
        profile_max_amounts in rules.yaml defines expected maximum
        transaction volumes per customer profile type.
        Amount within expected range for profile = false indicator.
        Amount 3x+ above expected max = true indicator.

    Signal 5 - Profile-to-alert-type consistency
        Certain alert types are expected for certain profiles.
        A Retail business owner doing cross-border wire transfers
        is their declared activity - likely legitimate.
        A Student doing the same is highly anomalous.

    Signal 6 - Historical disposition rate
        After analysts approve/reject cases via submit_review(),
        those outcomes are stored in alert_dispositions table.
        If this exact rule combination against this profile has
        historically resolved as false 85%+ of the time,
        that is a very strong false indicator.
        Returns neutral 0.5 if fewer than 10 historical samples exist.
"""

from typing import Any

from .database import get_customer, get_historical_fp_rate
from rag_pipeline.rule_engine import load_rule_config


# -- Rule classification ------------------------------------------------------
# Threshold-based rules require measured numeric values to breach.
# These are strong evidence of actual suspicious activity.
THRESHOLD_RULE_IDS = {
    "AML-001",  # Structuring / Smurfing - transaction count > threshold
    "AML-002",  # High Velocity - txn_per_day > threshold
    "AML-003",  # Below Threshold Structuring - avg amount in 70-99% band
    "AML-004",  # Large Value Transaction - total > large_amount threshold
    "AML-005",  # Profile Inconsistency - total > expected_max for profile
    "AML-006",  # High Risk Jurisdiction - destination in FATF list
    "AML-007",  # Rapid Fund Movement - days <= rapid_movement_days
    "AML-013",  # Account Type Mismatch - savings account high volume
}

# Keyword-only rules fire because a word exists in alert.pattern field.
# They require zero numeric evidence. Alone they are very weak signals.
KEYWORD_RULE_IDS = {
    "AML-008",  # Deposit Aggregation - substring match only
    "AML-009",  # Round Tripping - substring match only
    "AML-010",  # Cash Intensive Activity - substring match only
    "AML-011",  # Multi Account Layering - substring match only
    "AML-012",  # Confirmed Structuring Pattern - substring match only
}

# Alert types that are expected and therefore less suspicious
# for each customer profile. If the alert type matches what the
# customer is supposed to do, it is a weaker signal.
EXPECTED_ALERT_TYPES_BY_PROFILE: dict[str, list[str]] = {
    "Retail business owner": ["WIRE_TRANSFER", "CROSS_BORDER", "STRUCTURING", "TRADE"],
    "Salaried employee": ["LARGE_CASH", "DOMESTIC"],
    "Student": [],
    "Retired": ["LARGE_CASH", "DOMESTIC"],
}

# Scoring thresholds for final verdict
LIKELY_TRUE_THRESHOLD = 0.55
LIKELY_FALSE_THRESHOLD = 0.28


def score_false_alert_probability(
    alert: dict[str, Any],
    evidence_blocks: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Main entry point. Called from app.py create_new_case() after
    evaluate_rules() returns but before enrich_case() runs.

    Parameters:
        alert         - the full alert_payload dict from POST /cases
        evidence_blocks - the list returned by evaluate_rules(alert)

    Returns:
        {
            verdict: "LIKELY_FALSE" | "BORDERLINE" | "LIKELY_TRUE"
            true_positive_score: float 0.0 to 1.0
            signals: list of signal dicts explaining each decision
            rule_ids_evaluated: sorted list of rule IDs that fired
            recommendation: human-readable string of what will happen
        }
    """
    signals: list[dict[str, Any]] = []
    true_positive_score = 0.0

    txn = alert.get("transactions", {})
    profile = str(alert.get("customer_profile", ""))
    alert_type = str(alert.get("alert_type", "")).upper().replace(" ", "_")
    total_amount = float(txn.get("total_amount", 0))
    rule_count = len(evidence_blocks)

    config = load_rule_config()

    fired_ids = {b["rule_id"] for b in evidence_blocks}
    sorted_rule_ids = sorted(fired_ids)

    # -- Signal 1: Rule count and type quality ----------------------------
    threshold_fired = fired_ids & THRESHOLD_RULE_IDS
    keyword_fired = fired_ids & KEYWORD_RULE_IDS
    keyword_only = fired_ids.issubset(KEYWORD_RULE_IDS)
    threshold_count = len(threshold_fired)

    if threshold_count >= 3:
        true_positive_score += 0.30
        signals.append({
            "signal": "rule_type_quality",
            "direction": "TRUE",
            "value": threshold_count,
            "reason": f"{threshold_count} threshold-based rules fired - strong numeric evidence",
        })
    elif threshold_count == 2:
        true_positive_score += 0.18
        signals.append({
            "signal": "rule_type_quality",
            "direction": "WEAK_TRUE",
            "value": threshold_count,
            "reason": "2 threshold-based rules fired",
        })
    elif threshold_count == 1:
        true_positive_score += 0.08
        signals.append({
            "signal": "rule_type_quality",
            "direction": "WEAK",
            "value": threshold_count,
            "reason": "Only 1 threshold rule fired - marginal numeric evidence",
        })
    elif keyword_only:
        true_positive_score += 0.02
        signals.append({
            "signal": "rule_type_quality",
            "direction": "FALSE",
            "value": 0,
            "reason": (
                f"Only keyword pattern rules fired: {sorted(keyword_fired)}. "
                "These match on text in the pattern field - zero numeric evidence."
            ),
        })

    # -- Signal 2: Average rule confidence --------------------------------
    if rule_count > 0:
        avg_conf = round(
            sum(b["confidence"] for b in evidence_blocks) / rule_count, 3
        )
    else:
        avg_conf = 0.0

    if avg_conf >= 0.88:
        true_positive_score += 0.20
        signals.append({
            "signal": "avg_confidence",
            "direction": "TRUE",
            "value": avg_conf,
            "reason": f"High average rule confidence {avg_conf} - alerts well above thresholds",
        })
    elif avg_conf >= 0.70:
        true_positive_score += 0.10
        signals.append({
            "signal": "avg_confidence",
            "direction": "WEAK",
            "value": avg_conf,
            "reason": f"Medium average confidence {avg_conf}",
        })
    else:
        signals.append({
            "signal": "avg_confidence",
            "direction": "FALSE",
            "value": avg_conf,
            "reason": (
                f"Low average confidence {avg_conf} - alert barely breached "
                "thresholds, likely marginal transaction behaviour"
            ),
        })

    # -- Signal 3: KYC risk rating (single DB query) ----------------------
    customer = get_customer(str(alert.get("customer_id", "")))
    if customer:
        if not profile:
            profile = str(customer.get("occupation") or "")
        rating = str(customer.get("risk_rating", "LOW")).upper()
        if rating == "HIGH":
            true_positive_score += 0.20
            signals.append({
                "signal": "kyc_risk_rating",
                "direction": "TRUE",
                "value": rating,
                "reason": "Customer is HIGH KYC risk - alerts from this segment are more likely genuine",
            })
        elif rating == "MEDIUM":
            true_positive_score += 0.08
            signals.append({
                "signal": "kyc_risk_rating",
                "direction": "WEAK",
                "value": rating,
                "reason": "Customer is MEDIUM KYC risk",
            })
        else:
            signals.append({
                "signal": "kyc_risk_rating",
                "direction": "FALSE",
                "value": rating,
                "reason": (
                    "Customer is LOW KYC risk. "
                    "The majority of false positive alerts originate from LOW risk customers."
                ),
            })
    else:
        true_positive_score += 0.05
        signals.append({
            "signal": "kyc_risk_rating",
            "direction": "WEAK",
            "value": "UNKNOWN",
            "reason": "Customer not found in DB - treating cautiously",
        })

    # -- Signal 4: Profile-amount consistency -----------------------------
    profile_max_amounts = config.get("profile_max_amounts", {})
    defaults = config.get("defaults", {})
    profile_max = float(
        profile_max_amounts.get(profile)
        or defaults.get("expected_profile_max", 1_000_000)
    )

    ratio = round(total_amount / profile_max, 2) if profile_max > 0 else 0.0

    if ratio >= 3.0:
        true_positive_score += 0.15
        signals.append({
            "signal": "profile_amount_ratio",
            "direction": "TRUE",
            "value": ratio,
            "reason": (
                f"Amount INR {total_amount:,.0f} is {ratio}x the expected maximum "
                f"for {profile} profile (INR {profile_max:,.0f}) - highly anomalous"
            ),
        })
    elif ratio >= 1.0:
        true_positive_score += 0.07
        signals.append({
            "signal": "profile_amount_ratio",
            "direction": "WEAK",
            "value": ratio,
            "reason": f"Amount above profile maximum but within 3x ({ratio}x)",
        })
    else:
        signals.append({
            "signal": "profile_amount_ratio",
            "direction": "FALSE",
            "value": ratio,
            "reason": (
                f"Amount INR {total_amount:,.0f} is within the expected range "
                f"for {profile} profile (max INR {profile_max:,.0f})"
            ),
        })

    # -- Signal 5: Profile-to-alert-type consistency ----------------------
    expected_types = EXPECTED_ALERT_TYPES_BY_PROFILE.get(profile, [])
    pattern_consistent = any(e in alert_type for e in expected_types)

    if expected_types and pattern_consistent:
        signals.append({
            "signal": "profile_alert_type_consistency",
            "direction": "FALSE",
            "value": alert_type,
            "reason": (
                f"{alert_type} is consistent with declared activity "
                f"for {profile} profile - behaviour matches stated purpose"
            ),
        })
    elif not expected_types or not pattern_consistent:
        if profile == "Student" and total_amount > 100_000:
            true_positive_score += 0.10
            signals.append({
                "signal": "profile_alert_type_consistency",
                "direction": "TRUE",
                "value": alert_type,
                "reason": (
                    f"Student profile with {alert_type} of INR {total_amount:,.0f} "
                    "is highly inconsistent with declared student status"
                ),
            })
        else:
            true_positive_score += 0.04
            signals.append({
                "signal": "profile_alert_type_consistency",
                "direction": "WEAK",
                "value": alert_type,
                "reason": f"{alert_type} is not typical for {profile} profile",
            })

    # -- Signal 6: Historical false positive rate --------------------------
    historical_fp_rate = get_historical_fp_rate(sorted_rule_ids, profile)

    if historical_fp_rate == 0.5:
        true_positive_score += 0.05
        signals.append({
            "signal": "historical_fp_rate",
            "direction": "NEUTRAL",
            "value": historical_fp_rate,
            "reason": "Fewer than 10 historical samples for this rule+profile combination - neutral",
        })
    elif historical_fp_rate >= 0.85:
        true_positive_score -= 0.05
        signals.append({
            "signal": "historical_fp_rate",
            "direction": "FALSE",
            "value": historical_fp_rate,
            "reason": (
                f"This rule combination ({sorted_rule_ids}) against {profile} profile "
                f"has a {round(historical_fp_rate * 100)}% historical false positive rate"
            ),
        })
    elif historical_fp_rate <= 0.30:
        true_positive_score += 0.15
        signals.append({
            "signal": "historical_fp_rate",
            "direction": "TRUE",
            "value": historical_fp_rate,
            "reason": (
                f"Only {round(historical_fp_rate * 100)}% historical false positive rate "
                f"for this rule+profile combination - these usually result in genuine SARs"
            ),
        })
    else:
        true_positive_score += 0.05
        signals.append({
            "signal": "historical_fp_rate",
            "direction": "WEAK",
            "value": historical_fp_rate,
            "reason": f"Mixed historical outcomes ({round(historical_fp_rate * 100)}% FP rate)",
        })

    # -- Final verdict -----------------------------------------------------
    true_positive_score = round(max(0.0, min(1.0, true_positive_score)), 3)

    if true_positive_score >= LIKELY_TRUE_THRESHOLD:
        verdict = "LIKELY_TRUE"
        recommendation = (
            "Proceed to full pipeline: enrich_case -> evaluate_rules -> "
            "RAG retrieval -> Ollama narrative generation"
        )
    elif true_positive_score >= LIKELY_FALSE_THRESHOLD:
        verdict = "BORDERLINE"
        recommendation = (
            "Send to analyst triage queue. Analyst reviews rule summary only. "
            "No enrichment, no LLM, no ChromaDB. "
            "Analyst can escalate to full pipeline or close as false positive."
        )
    else:
        verdict = "LIKELY_FALSE"
        recommendation = (
            "Auto-close as likely false positive. "
            "No enrichment, no LLM, no ChromaDB queries. "
            "Disposition recorded for feedback loop."
        )

    return {
        "verdict": verdict,
        "true_positive_score": true_positive_score,
        "customer_profile_used": profile,
        "signals": signals,
        "rule_ids_evaluated": sorted_rule_ids,
        "threshold_rules_fired": sorted(threshold_fired),
        "keyword_rules_fired": sorted(keyword_fired),
        "recommendation": recommendation,
    }
