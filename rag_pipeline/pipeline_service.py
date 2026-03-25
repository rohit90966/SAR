from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

import chromadb
import ollama
from sentence_transformers import SentenceTransformer

try:
    from .rule_engine import build_rag_query, calculate_risk_score, evaluate_rules
except ImportError:
    from rule_engine import build_rag_query, calculate_risk_score, evaluate_rules


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_ALERT_PATH = ROOT_DIR / "data" / "alert_case.json"
VECTOR_DB_PATH = Path(os.getenv("CHROMA_DB_PATH", ROOT_DIR / "rag_pipeline" / "vector_db"))
PROMPT_VERSION = "local-fastapi-v1"
DEFAULT_MODEL_NAME = os.getenv("OLLAMA_MODEL", "mistral:7b")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_alert_from_file(alert_path: str | Path | None = None) -> dict[str, Any]:
    path = Path(alert_path or DEFAULT_ALERT_PATH)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def mask_identifier(value: str | None) -> str | None:
    if not value:
        return value
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def mask_name(value: str | None) -> str | None:
    if not value:
        return value
    parts = value.split()
    masked_parts = []
    for part in parts:
        if len(part) <= 1:
            masked_parts.append("*")
        else:
            masked_parts.append(f"{part[0]}{'*' * (len(part) - 1)}")
    return " ".join(masked_parts)


def mask_alert(alert: dict[str, Any]) -> dict[str, Any]:
    masked = copy.deepcopy(alert)
    masked["customer_name"] = mask_name(masked.get("customer_name"))
    masked["customer_id"] = mask_identifier(masked.get("customer_id"))
    return masked


def split_paragraphs(text: str) -> list[str]:
    return [paragraph.strip() for paragraph in text.split("\n\n") if paragraph.strip()]


def split_sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+", text.strip())
    return [part.strip() for part in parts if part.strip()]


def normalise_number_tokens(text: str) -> set[str]:
    return {token.replace(",", "") for token in re.findall(r"\d+(?:,\d+)*(?:\.\d+)?", text)}


def build_text_diff(original: str, updated: str) -> list[dict[str, Any]]:
    import difflib

    original_lines = original.splitlines()
    updated_lines = updated.splitlines()
    diff = difflib.unified_diff(
        original_lines,
        updated_lines,
        fromfile="generated",
        tofile="analyst",
        lineterm="",
    )
    return [{"line": line} for line in diff]


@lru_cache(maxsize=1)
def get_embedding_model() -> SentenceTransformer:
    return SentenceTransformer("all-MiniLM-L6-v2")


@lru_cache(maxsize=1)
def get_collection():
    client = chromadb.PersistentClient(path=str(VECTOR_DB_PATH))
    return client.get_collection("sar_knowledge")


class SarRagService:
    def __init__(self, model_name: str = DEFAULT_MODEL_NAME) -> None:
        self.model_name = model_name

    def _chat_with_fallback(
        self,
        model_name: str,
        system_prompt: str,
        user_prompt: str,
        model_options: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            return ollama.chat(
                model=model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                options=model_options,
            )
        except Exception as exc:
            message = str(exc).lower()
            if "cuda" not in message and "gpu" not in message:
                raise

            fallback_options = dict(model_options)
            fallback_options["num_gpu"] = 0
            return ollama.chat(
                model=model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                options=fallback_options,
            )

    def process_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        case_started_at = utc_now()
        masked_alert = mask_alert(alert)
        audit_events: list[dict[str, Any]] = [
            {
                "event_type": "CASE_INGESTED",
                "payload": {
                    "alert_id": alert["alert_id"],
                    "masked_alert": masked_alert,
                    "timestamp": case_started_at,
                },
            }
        ]

        evidence_blocks = evaluate_rules(alert)
        risk_score, risk_level = calculate_risk_score(evidence_blocks)
        evidence_pack = self._build_evidence_pack(alert, evidence_blocks, risk_score, risk_level)
        audit_events.append(
            {
                "event_type": "RULES_EVALUATED",
                "payload": {
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "rule_count": len(evidence_blocks),
                    "evidence_blocks": evidence_blocks,
                },
            }
        )

        if not evidence_blocks:
            final_sar = {
                "customer_name": alert["customer_name"],
                "customer_id": alert["customer_id"],
                "account_type": alert["account_type"],
                "alert_id": alert["alert_id"],
                "alert_type": alert["alert_type"],
                "risk_score": risk_score,
                "risk_level": risk_level,
                "rules_triggered": 0,
                "narrative": "No suspicious activity threshold was met by the deterministic rule engine. No SAR draft was generated and the case has been closed.",
                "generated_at": utc_now(),
                "status": "NO_SAR_REQUIRED",
            }
            validation = {
                "passed": True,
                "checks": [
                    {
                        "name": "no_rules_triggered",
                        "passed": True,
                        "details": "Case closed without narrative generation because no AML rules fired.",
                    }
                ],
                "failed_checks": [],
            }
            return {
                "status": "NO_SAR_REQUIRED",
                "masked_alert": masked_alert,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "evidence_pack": evidence_pack,
                "retrieval_payload": {},
                "prompt_payload": {},
                "validation_payload": validation,
                "final_sar": final_sar,
                "analyst_traceability": [],
                "audit_events": audit_events,
            }

        query = build_rag_query(evidence_blocks, masked_alert)
        retrieval_payload = self._retrieve_context(query)
        audit_events.append(
            {
                "event_type": "RAG_RETRIEVAL_COMPLETED",
                "payload": retrieval_payload,
            }
        )

        prompt_payload = self._build_prompt_bundle(masked_alert, evidence_blocks, retrieval_payload)

        # ── CHANGE 3: generate with one automatic retry if word count is too low ──
        raw_response = self._chat_with_fallback(
            model_name=self.model_name,
            system_prompt=prompt_payload["system_prompt"],
            user_prompt=prompt_payload["user_prompt"],
            model_options=prompt_payload["model_options"],
        )
        narrative = self._post_process_narrative(raw_response["message"]["content"], alert)

        if len(narrative.split()) < 280:
            raw_response = self._chat_with_fallback(
                model_name=self.model_name,
                system_prompt=prompt_payload["system_prompt"],
                user_prompt=prompt_payload["user_prompt"],
                model_options=prompt_payload["model_options"],
            )
            narrative = self._post_process_narrative(raw_response["message"]["content"], alert)
        # ── end CHANGE 3 ──

        sentence_traceability = self._build_sentence_traceability(
            narrative,
            evidence_blocks,
            retrieval_payload["documents"],
        )
        validation_payload = self._validate_narrative(alert, narrative)

        final_sar = {
            "customer_name": alert["customer_name"],
            "customer_id": alert["customer_id"],
            "account_type": alert["account_type"],
            "alert_id": alert["alert_id"],
            "alert_type": alert["alert_type"],
            "risk_score": risk_score,
            "risk_level": risk_level,
            "rules_triggered": len(evidence_blocks),
            "narrative": narrative,
            "sentence_traceability": sentence_traceability,
            "generated_at": utc_now(),
            "status": "PENDING_ANALYST_REVIEW",
        }

        audit_events.extend(
            [
                {
                    "event_type": "LLM_GENERATION_COMPLETED",
                    "payload": {
                        "model_name": self.model_name,
                        "model_options": prompt_payload["model_options"],
                        "prompt_version": prompt_payload["prompt_version"],
                        "prompt_sha256": prompt_payload["prompt_sha256"],
                        "prompt_sha": prompt_payload["prompt_sha"],
                        "raw_response": raw_response,
                    },
                },
                {
                    "event_type": "VALIDATION_COMPLETED",
                    "payload": validation_payload,
                },
                {
                    "event_type": "CASE_READY_FOR_REVIEW",
                    "payload": {
                        "status": "PENDING_ANALYST_REVIEW",
                        "generated_at": final_sar["generated_at"],
                    },
                },
            ]
        )

        return {
            "status": "PENDING_ANALYST_REVIEW",
            "masked_alert": masked_alert,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "evidence_pack": evidence_pack,
            "retrieval_payload": retrieval_payload,
            "prompt_payload": prompt_payload,
            "validation_payload": validation_payload,
            "final_sar": final_sar,
            "analyst_traceability": sentence_traceability,
            "audit_events": audit_events,
        }

    def replay_case(self, case_record: dict[str, Any]) -> dict[str, Any]:
        prompt_payload = case_record.get("prompt_payload") or {}
        if not prompt_payload:
            return {
                "replayed": False,
                "reason": "Prompt payload unavailable for this case.",
                "replayed_at": utc_now(),
            }

        raw_response = self._chat_with_fallback(
            model_name=prompt_payload.get("model_name", self.model_name),
            system_prompt=prompt_payload["system_prompt"],
            user_prompt=prompt_payload["user_prompt"],
            model_options=prompt_payload.get("model_options", {"num_ctx": 2048, "temperature": 0.2, "top_p": 0.9}),
        )

        alert_payload = case_record["alert_payload"]
        replay_narrative = self._post_process_narrative(raw_response["message"]["content"], alert_payload)
        original_narrative = case_record.get("final_sar", {}).get("narrative", "")
        replay_matches = replay_narrative == original_narrative
        return {
            "replayed": True,
            "replayed_at": utc_now(),
            "replay_matches_original": replay_matches,
            "replayed_narrative": replay_narrative,
            "original_narrative": original_narrative,
            "raw_response": raw_response,
        }

    def _retrieve_context(self, query: str, n_results: int = 5) -> dict[str, Any]:
        model = get_embedding_model()
        collection = get_collection()
        query_embedding = model.encode([query])
        results = collection.query(query_embeddings=query_embedding, n_results=n_results)
        snapshot = {
            "snapshot_id": collection.name,
            "total_docs": collection.count(),
            "captured_at": utc_now(),
        }
        documents = []
        for index, document in enumerate(results["documents"][0]):
            distance = float(results["distances"][0][index])
            documents.append(
                {
                    "id": results["ids"][0][index],
                    "document": document,
                    "distance": distance,
                    "similarity_score": round(max(0.0, 1 - distance), 4),
                    "metadata": results["metadatas"][0][index],
                }
            )

        return {
            "query_used": query,
            "documents": documents,
            "corpus_snapshot": snapshot,
            "retrieval_timestamp": utc_now(),
        }

    def _build_evidence_pack(
        self,
        alert: dict[str, Any],
        evidence_blocks: list[dict[str, Any]],
        risk_score: float,
        risk_level: str,
    ) -> dict[str, Any]:
        transaction_details = self._build_transaction_details(alert)
        financials = self._build_financials_block(alert)
        return {
            "alert_id": alert["alert_id"],
            "alert_type": alert["alert_type"],
            "risk_score": risk_score,
            "risk_level": risk_level,
            "masked_alert": mask_alert(alert),
            "transaction_details": transaction_details,
            "customer_financials": financials,
            "rule_summary": [
                {
                    "rule_id": block["rule_id"],
                    "rule_name": block["rule_name"],
                    "confidence": block["confidence"],
                    "observation": block["observation"],
                    "why_flagged": block["audit_reason"]["why_flagged"],
                    "regulation": block["audit_reason"]["regulation"],
                }
                for block in evidence_blocks
            ],
            "generated_at": utc_now(),
        }

    def _build_transaction_details(self, alert: dict[str, Any]) -> dict[str, Any]:
        transactions = alert["transactions"]
        avg_amount = round(transactions["total_amount"] / transactions["transaction_count"])
        details = {
            "alert_type": alert["alert_type"],
            "account_type": alert["account_type"],
            "customer_profile": alert["customer_profile"],
            "transaction_count": transactions["transaction_count"],
            "total_amount": transactions["total_amount"],
            "time_window_days": transactions["time_window_days"],
            "average_transaction_amount": avg_amount,
            "destination_country": transactions.get("destination_country", "DOMESTIC"),
            # ── CHANGE 2: include velocity in transaction details ──
            "txn_per_day": round(
                transactions["transaction_count"] / max(transactions["time_window_days"], 1), 1
            ),
        }
        for optional_key in ["min_transaction_amount", "max_transaction_amount", "reporting_threshold"]:
            if optional_key in transactions:
                details[optional_key] = transactions[optional_key]
        return details

    def _build_financials_block(self, alert: dict[str, Any]) -> dict[str, Any] | None:
        if "customer_financials" not in alert:
            return None

        financials = copy.deepcopy(alert["customer_financials"])
        # ── CHANGE 3 (part): strip None values so they never reach the prompt ──
        financials = {k: v for k, v in financials.items() if v is not None}

        avg_monthly = financials.get("avg_monthly_deposits_12m")
        if avg_monthly:
            deviation = round(((alert["transactions"]["total_amount"] - avg_monthly) / avg_monthly) * 100, 1)
            financials["deviation_from_baseline_pct"] = deviation
        return financials

    def _build_prompt_bundle(
        self,
        alert: dict[str, Any],
        evidence_blocks: list[dict[str, Any]],
        retrieval_payload: dict[str, Any],
    ) -> dict[str, Any]:
        transaction_details = self._build_transaction_details(alert)
        financials = self._build_financials_block(alert)
        evidence_summary = "\n".join(
            [
                f"- {block['rule_id']} ({block['rule_name']}): {block['observation']} [confidence: {block['confidence']}] — {block['audit_reason']['why_flagged']}"
                for block in evidence_blocks
            ]
        )

        # ── CHANGE 1: build a formatted rule list for paragraph 4 ──
        rule_list_for_p4 = ", ".join(
            f"{block['rule_name']} ({block['rule_id']})"
            for block in evidence_blocks
        )

        context_parts = []
        for item in retrieval_payload["documents"]:
            doc_type = item["metadata"].get("type", "general")
            if doc_type in {"typology", "guideline"}:
                context_parts.append(item["document"])
            else:
                context_parts.append(
                    "[WRITING STYLE AND STRUCTURE REFERENCE ONLY — DO NOT COPY ANY FIGURES OR AMOUNTS FROM THIS SECTION]\n"
                    f"{item['document']}"
                )
        context = "\n\n".join(context_parts)

        transaction_lines = [
            "Transaction Details (use ONLY these exact figures — no others):",
            f"- Alert Type            : {transaction_details['alert_type']}",
            f"- Account Type          : {transaction_details['account_type']}",
            f"- Customer Profile      : {transaction_details['customer_profile']}",
            f"- Transaction Count     : {transaction_details['transaction_count']}",
            f"- Total Amount          : INR {transaction_details['total_amount']}",
            f"- Time Window           : {transaction_details['time_window_days']} days",
            f"- Average Txn Amount    : INR {transaction_details['average_transaction_amount']}",
            f"- Destination Country   : {transaction_details['destination_country']}",
            # ── CHANGE 2: velocity line added to prompt data ──
            f"- Transaction Velocity  : {transaction_details['txn_per_day']} txn/day (institutional threshold: 5 txn/day)",
        ]
        if "min_transaction_amount" in transaction_details:
            transaction_lines.append(f"- Min Transaction       : INR {transaction_details['min_transaction_amount']}")
        if "max_transaction_amount" in transaction_details:
            transaction_lines.append(f"- Max Transaction       : INR {transaction_details['max_transaction_amount']}")
        if "reporting_threshold" in transaction_details:
            transaction_lines.append(f"- Reporting Threshold   : INR {transaction_details['reporting_threshold']}")

        financial_lines = []
        if financials:
            financial_lines = [
                "Customer Financials (use ONLY these exact figures — no others):",
                f"- Declared Monthly Income      : INR {financials.get('declared_monthly_income', 'NOT PROVIDED')}",
                f"- Avg Monthly Deposits (12m)   : INR {financials.get('avg_monthly_deposits_12m', 'NOT PROVIDED')}",
                f"- Historical Txn Count/Month   : {financials.get('historical_baseline_txn_count', 'NOT PROVIDED')}",
            ]
            if "deviation_from_baseline_pct" in financials:
                financial_lines.append(
                    f"- Deviation from Baseline      : {financials['deviation_from_baseline_pct']}% increase over historical baseline"
                )

        system_prompt = f"""IMPORTANT OUTPUT FORMAT — READ FIRST:
Your response must contain ONLY the five paragraph SAR narrative.
Start your response directly with the first word of paragraph 1.
Do NOT write any introduction, note, bullet list, heading, or section label.

You are a senior AML compliance analyst at a major financial institution.
You write Suspicious Activity Reports filed with regulatory authorities such as FinCEN, FIU-India, and the National Crime Agency.

CRITICAL DATA RULES:
1. Use ONLY numbers explicitly given in Transaction Details and Customer Financials.
2. Never include the customer name, customer ID, or any account number.
3. Never add branch locations, dates, counterparties, or documentation facts that were not provided.
4. The primary AML typology for this case is exactly {alert['alert_type']}.
5. Use the AML Reference Knowledge only for typology definitions and writing style.

WRITING STYLE:
- Third person
- Past tense
- Professional compliance tone
- All monetary amounts prefixed with INR
- Length between 280 and 380 words
- Never write data labels like "Total inbound:" or "Residual balance:" — always write full sentences

FIVE PARAGRAPH STRUCTURE:
Paragraph 1: filing institution, account type, customer profile, alert type, monitoring period.
Paragraph 2: suspicious transaction behaviour using only total amount, time window, destination country. End with a sentence describing the near-zero residual balance and pass-through mechanism.
Paragraph 3: deviation from baseline percentage, average transaction amount vs reporting threshold, AND the transaction velocity ({transaction_details['txn_per_day']} txn/day) vs the institutional threshold of 5 txn/day.
Paragraph 4: reason for suspicion, the exact typology name, AND name the following triggered rules explicitly by name and ID: {rule_list_for_p4}.
Paragraph 5: filing decision citing PMLA Section 12, enhanced monitoring, FIU escalation, and source of funds request.
"""

        user_prompt = "\n".join(
            [
                "Write a SAR narrative using ONLY the data provided below.",
                *transaction_lines,
                *financial_lines,
                "",
                "Triggered Compliance Rules — Evidence Summary:",
                evidence_summary,
                "",
                "AML Reference Knowledge (writing style and typology definitions ONLY — never copy figures or amounts from this section):",
                context,
                "",
                "FINAL CHECKLIST:",
                f"- Start directly with paragraph 1 and use {alert['alert_type']} as the typology name in paragraph 4.",
                "- No customer name, customer ID, or account number anywhere.",
                "- No placeholder text in square brackets.",
                "- No paragraph labels or closing note after paragraph 5.",
                f"- Paragraph 3 must state the {transaction_details['txn_per_day']} txn/day velocity and how it exceeds the 5 txn/day threshold.",
                f"- Paragraph 4 must name these rules: {rule_list_for_p4}.",
                "- Minimum 280 words total.",
            ]
        )

        prompt_sha = hashlib.sha256(f"{system_prompt}\n---\n{user_prompt}".encode("utf-8")).hexdigest()
        return {
            "prompt_version": PROMPT_VERSION,
            "prompt_sha256": prompt_sha,
            "prompt_sha": prompt_sha,
            "model_name": self.model_name,
            "model_options": {"num_ctx": 4096, "temperature": 0.2, "top_p": 0.9},
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
        }

    def _post_process_narrative(self, text: str, alert: dict[str, Any]) -> str:
        preamble_phrases = {
            "here is the sar narrative",
            "here's the sar narrative",
            "here is the narrative",
            "based on the compliance findings",
            "sar narrative:",
            "narrative:",
        }
        lines = []
        for line in text.strip().splitlines():
            if line.strip().lower() in preamble_phrases:
                continue
            lines.append(line)
        cleaned = "\n".join(lines).strip()

        replacements = {
            "[Filing Institution Name]": "The filing institution",
            "[FILING INSTITUTION NAME]": "The filing institution",
            "[Bank Name]": "The filing institution",
            "[CUSTOMER NAME]": "the account holder",
            "[Customer Name]": "the account holder",
            "[CUSTOMER ID]": "",
            "[ACCOUNT NUMBER]": "",
            "[ACCOUNT TYPE]": alert["account_type"],
            "[ALERT DATE]": "the monitoring period",
            "[START DATE]": "the monitoring period",
            "[END DATE]": "the monitoring period",
            "[APPLICABLE REGULATION]": "PMLA Section 12",
        }
        for placeholder, replacement in replacements.items():
            cleaned = cleaned.replace(placeholder, replacement)
        return cleaned.strip()

    def _build_sentence_traceability(
        self,
        narrative: str,
        evidence_blocks: list[dict[str, Any]],
        retrieved_documents: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        traceability = []
        sentences = split_sentences(narrative)
        for sentence in sentences:
            lowered = sentence.lower()
            linked_rules = []
            for block in evidence_blocks:
                keywords = [block["rule_name"], block["rule_id"], block["observation"], block["audit_reason"]["why_flagged"]]
                if any(keyword.lower().split()[0] in lowered for keyword in keywords if keyword):
                    linked_rules.append(
                        {
                            "rule_id": block["rule_id"],
                            "rule_name": block["rule_name"],
                            "confidence": block["confidence"],
                        }
                    )
            if not linked_rules:
                linked_rules = [
                    {
                        "rule_id": block["rule_id"],
                        "rule_name": block["rule_name"],
                        "confidence": block["confidence"],
                    }
                    for block in evidence_blocks[:2]
                ]

            linked_docs = []
            for item in retrieved_documents[:3]:
                document_text = item["document"].lower()
                if any(token in document_text for token in lowered.split()[:4]):
                    linked_docs.append(
                        {
                            "document_id": item["id"],
                            "doc_type": item["metadata"].get("type", "general"),
                            "similarity_score": item["similarity_score"],
                        }
                    )
            if not linked_docs:
                linked_docs = [
                    {
                        "document_id": item["id"],
                        "doc_type": item["metadata"].get("type", "general"),
                        "similarity_score": item["similarity_score"],
                    }
                    for item in retrieved_documents[:1]
                ]

            explainability_score = round(min(0.99, 0.55 + (0.1 * len(linked_rules)) + (0.05 * len(linked_docs))), 2)
            traceability.append(
                {
                    "sentence": sentence,
                    "linked_rules": linked_rules,
                    "linked_documents": linked_docs,
                    "explainability_score": explainability_score,
                    "flagged_for_review": explainability_score < 0.75,
                }
            )
        return traceability

    def _validate_narrative(self, alert: dict[str, Any], narrative: str) -> dict[str, Any]:
        paragraphs = split_paragraphs(narrative)
        words = re.findall(r"\b\w+\b", narrative)
        numbers_in_narrative = normalise_number_tokens(narrative)
        allowed_numbers = {
            "12",
            str(alert["transactions"]["transaction_count"]),
            str(alert["transactions"]["total_amount"]),
            str(alert["transactions"]["time_window_days"]),
            str(round(alert["transactions"]["total_amount"] / alert["transactions"]["transaction_count"])),
        }
        if "reporting_threshold" in alert["transactions"]:
            allowed_numbers.add(str(alert["transactions"]["reporting_threshold"]))
        if "customer_financials" in alert:
            for value in alert["customer_financials"].values():
                if value is not None:
                    allowed_numbers.add(str(value))
            avg_monthly = alert["customer_financials"].get("avg_monthly_deposits_12m")
            if avg_monthly:
                deviation = round(((alert["transactions"]["total_amount"] - avg_monthly) / avg_monthly) * 100, 1)
                allowed_numbers.add(str(deviation))

        # ── CHANGE 2: allow velocity figure in narrative ──
        txn_per_day = round(
            alert["transactions"]["transaction_count"] / max(alert["transactions"]["time_window_days"], 1), 1
        )
        allowed_numbers.add(str(txn_per_day))
        allowed_numbers.add("5")  # institutional velocity threshold

        checks = [
            {
                "name": "five_paragraphs",
                "passed": len(paragraphs) == 5,
                "details": f"Found {len(paragraphs)} paragraphs.",
            },
            {
                # ── CHANGE 3: raised minimum word count from 250 to 280 ──
                "name": "word_count_range",
                "passed": 280 <= len(words) <= 400,
                "details": f"Narrative contains {len(words)} words.",
            },
            {
                "name": "no_pii_exposed",
                "passed": alert["customer_name"].lower() not in narrative.lower() and alert["customer_id"].lower() not in narrative.lower(),
                "details": "Customer name and customer ID are excluded from the narrative.",
            },
            {
                "name": "no_placeholders",
                "passed": re.search(r"\[[^\]]+\]", narrative) is None,
                "details": "Narrative does not contain unresolved placeholders.",
            },
            {
                "name": "correct_typology_used",
                "passed": alert["alert_type"].lower() in narrative.lower(),
                "details": f"Narrative references typology {alert['alert_type']}.",
            },
            {
                "name": "no_bullet_formatting",
                "passed": "*" not in narrative and "- " not in narrative,
                "details": "Narrative remains in paragraph prose format.",
            },
            {
                "name": "contains_filing_statement",
                "passed": "filing" in narrative.lower() and "sar" in narrative.lower(),
                "details": "Narrative states the filing decision.",
            },
            {
                "name": "numbers_are_evidence_bounded",
                "passed": numbers_in_narrative.issubset(allowed_numbers),
                "details": f"Allowed numbers: {sorted(allowed_numbers)}; found: {sorted(numbers_in_narrative)}",
            },
        ]
        failed_checks = [check["name"] for check in checks if not check["passed"]]
        return {
            "passed": not failed_checks,
            "checks": checks,
            "failed_checks": failed_checks,
            "validated_at": utc_now(),
        }


def export_case_files(result: dict[str, Any], output_dir: str | Path | None = None) -> tuple[Path, Path]:
    destination = Path(output_dir or ROOT_DIR / "rag_pipeline")
    destination.mkdir(parents=True, exist_ok=True)
    final_sar = result["final_sar"]
    alert_id = final_sar["alert_id"]
    sar_path = destination / f"final_sar_{alert_id}.json"
    audit_path = destination / f"audit_{alert_id}.json"

    audit_payload = {
        "masked_alert": result["masked_alert"],
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "evidence_pack": result["evidence_pack"],
        "retrieval_payload": result["retrieval_payload"],
        "prompt_payload": {
            key: value
            for key, value in result["prompt_payload"].items()
            if key not in {"system_prompt", "user_prompt"}
        },
        "validation_payload": result["validation_payload"],
        "audit_events": result["audit_events"],
    }

    sar_path.write_text(json.dumps(final_sar, indent=2), encoding="utf-8")
    audit_path.write_text(json.dumps(audit_payload, indent=2), encoding="utf-8")
    return sar_path, audit_path