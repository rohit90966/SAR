from __future__ import annotations

import hashlib
import io
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import chromadb
import ollama
from ruamel.yaml import YAML as RuamelYAML
from sentence_transformers import SentenceTransformer
import yaml

try:
    import pdfplumber

    _HAS_PDFPLUMBER = True
except ImportError:
    _HAS_PDFPLUMBER = False

try:
    from docx import Document as DocxDocument

    _HAS_DOCX = True
except ImportError:
    _HAS_DOCX = False

ROOT_DIR = Path(__file__).resolve().parent.parent
RULES_YAML_PATH = ROOT_DIR / "rules.yaml"
REGULATION_REGISTRY_PATH = ROOT_DIR / "data" / "regulation_registry.json"
DEFAULT_MODEL = "mistral:7b"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
VECTOR_DB_PATH = os.getenv("CHROMA_DB_PATH", "./vector_db")
REGULATION_COLLECTION_NAME = "sar_knowledge"


VALID_CONTEXT_PATHS: set[str] = {
    "txn.transaction_count",
    "txn.total_amount",
    "txn.time_window_days",
    "txn.destination_country",
    "txn.reporting_threshold",
    "derived.txn_per_day",
    "derived.avg_amount",
    "derived.lower_band",
    "derived.upper_band",
    "derived.expected_max",
    "derived.destination",
    "derived.pattern",
    "derived.pattern_lower",
    "crypto_context.on_chain_hops",
    "crypto_context.mixer_detected",
    "crypto_context.exchange_registered_fiu",
    "crypto_context.conversion_direction",
    "crypto_context.defi_protocol_used",
    "alert.customer_profile",
    "alert.account_type",
    "customer.customer_profile",
    "customer.account_type",
    "thresholds.reporting_threshold",
    "thresholds.structuring_txn_count",
    "thresholds.velocity_per_day",
    "thresholds.large_amount",
    "thresholds.rapid_movement_days",
}


THRESHOLD_KEYS: dict[str, str] = {
    "reporting_threshold": "Maximum transaction amount before mandatory reporting (INR)",
    "structuring_txn_count": "Minimum transaction count to trigger structuring rule",
    "velocity_per_day": "Maximum transactions per day before velocity rule fires",
    "large_amount": "Large value transaction threshold (INR)",
    "rapid_movement_days": "Maximum days for rapid fund movement / layering rule",
    "high_risk_countries": "High-risk jurisdiction list used in jurisdiction risk checks",
}


COMPLIANCE_KEYWORDS: list[str] = [
    "threshold",
    "limit",
    "must",
    "shall",
    "report",
    "exceed",
    "transaction",
    "amount",
    "count",
    "days",
    "window",
    "period",
    "suspicious",
    "flag",
    "notify",
    "file",
    "sar",
    "fiu",
    "rbi",
    "pmla",
    "fatf",
    "aml",
    "kyc",
    "structuring",
    "velocity",
    "crore",
    "lakh",
    "rupee",
    "inr",
]


RULE_TYPE_LABELS: list[str] = [
    "LARGE_TRANSACTION",
    "STRUCTURING",
    "HIGH_VELOCITY",
    "JURISDICTION_RISK",
    "RAPID_MOVEMENT",
    "CRYPTO_EXPOSURE",
    "PROFILE_MISMATCH",
    "NEW_RULE",
]


RULE_TO_THRESHOLD_MAP = {
    "STRUCTURING": ["structuring_txn_count", "reporting_threshold"],
    "HIGH_VELOCITY": ["velocity_per_day"],
    "LARGE_TRANSACTION": ["large_amount"],
    "JURISDICTION_RISK": ["high_risk_countries"],
    "RAPID_MOVEMENT": ["rapid_movement_days"],
}


RULE_TYPE_TO_RULE_IDS: dict[str, list[str]] = {
    "STRUCTURING": ["AML-001", "AML-003"],
    "HIGH_VELOCITY": ["AML-002"],
    "LARGE_TRANSACTION": ["AML-004"],
    "JURISDICTION_RISK": ["AML-006"],
    "RAPID_MOVEMENT": ["AML-007"],
}


def load_rules_yaml() -> dict[str, Any]:
    with RULES_YAML_PATH.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def extract_rule_entities(rule_obj: dict[str, Any]) -> list[str]:
    entities: list[str] = []
    for cond in rule_obj.get("conditions", []) or []:
        if not isinstance(cond, dict):
            continue
        if "path" in cond:
            entities.append(str(cond["path"]))
        if "value_ref" in cond:
            entities.append(str(cond["value_ref"]))
        if "list_ref" in cond:
            entities.append(str(cond["list_ref"]))

    audit = rule_obj.get("audit_reason", {}) or {}
    if isinstance(audit, dict) and "regulation" in audit:
        entities.append(str(audit["regulation"]))

    return sorted(set(entities))


def retrieve_rule_context(entities: list[str], collection: Any) -> list[str]:
    if not entities or collection is None:
        return []

    query = " ".join(entities)
    try:
        results = collection.query(query_texts=[query], n_results=5)
    except Exception:
        return []

    docs = results.get("documents") or []
    if not docs:
        return []
    if isinstance(docs[0], list):
        return [d for d in docs[0] if isinstance(d, str)]
    return [d for d in docs if isinstance(d, str)]


def parse_llm_result(raw_result: Any, allowed_keys: list[str]) -> dict[str, Any]:
    default = {
        "changed": False,
        "parameter": None,
        "new_value": None,
        "evidence": "",
    }

    result: dict[str, Any]
    if isinstance(raw_result, str):
        text = raw_result.strip()
        try:
            result = json.loads(text)
        except Exception:
            # Tolerate extra wrapper text around JSON payload.
            start_obj = text.find("{")
            end_obj = text.rfind("}")
            if start_obj == -1 or end_obj == -1 or end_obj <= start_obj:
                print(f"[LLM PARSE] JSON parse failed: {text[:200]}")
                return default
            try:
                result = json.loads(text[start_obj : end_obj + 1])
            except Exception:
                print(f"[LLM PARSE] JSON parse failed: {text[:200]}")
                return default
    elif isinstance(raw_result, dict):
        result = raw_result
    else:
        return default

    changed = bool(result.get("changed", False))
    parameter = result.get("parameter")
    value: Any = result.get("new_value")
    evidence = str(result.get("evidence", ""))

    parameter_synonyms = {
        "reporting_threshold": "large_amount",
        "ctr_threshold": "large_amount",
        "cash_threshold": "large_amount",
        "transaction_limit": "large_amount",
        "txn_count": "structuring_txn_count",
        "transaction_count": "structuring_txn_count",
        "velocity": "velocity_per_day",
        "txn_per_day": "velocity_per_day",
        "countries": "high_risk_countries",
        "jurisdictions": "high_risk_countries",
    }

    if parameter is not None:
        parameter = str(parameter).lower().strip()
        parameter = parameter_synonyms.get(parameter, parameter)

    if parameter not in allowed_keys:
        print(f"[LLM PARSE] dropped invalid parameter: {parameter}")
        return default

    if isinstance(value, str):
        value_lower = value.lower().strip()
        number_match = re.findall(r"\d+(?:\.\d+)?", value_lower)
        if "lakh" in value_lower and number_match:
            value = float(number_match[0]) * 100000
        elif "million" in value_lower and number_match:
            value = float(number_match[0]) * 1000000
        elif "crore" in value_lower and number_match:
            value = float(number_match[0]) * 10000000
        elif number_match:
            value = float(number_match[0])

    if changed and not evidence:
        print("[LLM PARSE] missing evidence in changed decision")

    return {
        "changed": changed,
        "parameter": parameter,
        "new_value": value,
        "evidence": evidence,
    }


def detect_threshold_change(
    llm: Any,
    rule: dict[str, Any],
    retrieved_chunks: list[str],
    allowed_keys: list[str],
    current_values: dict[str, Any],
) -> dict[str, Any]:
    prompt = f"""
You are an AML regulation analysis engine.

Rule (from rules.yaml):
{json.dumps(rule, ensure_ascii=False, indent=2)}

Allowed Parameters (ONLY update these):
{json.dumps(allowed_keys, ensure_ascii=False, indent=2)}

Current parameter values:
{json.dumps(current_values, ensure_ascii=False, indent=2)}

Retrieved Regulatory Context:
{json.dumps(retrieved_chunks, ensure_ascii=False, indent=2)}

IMPORTANT NORMALIZATION (VERY STRICT)

Map all of these to large_amount:
- cash transaction reporting threshold
- CTR threshold
- reporting threshold
- cash reporting limit

Map all of these to structuring_txn_count:
- transaction count threshold
- number of transactions

Map all of these to velocity_per_day:
- transactions per day
- daily transaction velocity

Map all of these to high_risk_countries:
- high risk countries
- jurisdictions list

RULES:
1. ONLY update parameters present in allowed_keys
2. If no clear numeric or list value, return changed=false
3. If value is same as existing, return changed=false
4. If unsure, return changed=false
5. ALWAYS extract supporting evidence (exact text snippet)

You are analyzing the rule: {rule.get('id')} - {rule.get('name')}
The ONLY parameter you may update for this rule is: {allowed_keys}
Extract ONLY the threshold value that applies to: {allowed_keys[0] if allowed_keys else 'unknown'}
Do NOT extract values for other parameters even if mentioned in context.

OUTPUT FORMAT (STRICT JSON):
{{
  "changed": true/false,
    "parameter": "<one of allowed_keys or null>",
  "new_value": number or null,
  "evidence": "exact sentence"
}}

Do NOT rewrite the rule.
Do NOT update multiple parameters.
Do NOT return any text outside JSON.
""".strip()

    raw = llm(prompt)
    if isinstance(raw, dict) and "_error" in raw:
        return {"changed": False, "parameter": None, "new_value": None, "evidence": ""}
    result = parse_llm_result(raw, allowed_keys)
    if (
        result.get("changed") is True
        and not str(result.get("evidence", "")).strip()
        and result.get("new_value") is not None
    ):
        result["evidence"] = f"Regulation states new threshold of {result['new_value']}"
    return result


def _get_regulation_collection() -> Any | None:
    try:
        client = chromadb.PersistentClient(path=str(VECTOR_DB_PATH))
        return client.get_collection(REGULATION_COLLECTION_NAME)
    except Exception:
        return None


def find_rule_by_id(rules_config: dict[str, Any], rule_id: str) -> dict[str, Any] | None:
    rules = rules_config.get("rules", [])
    if not isinstance(rules, list):
        return None

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if str(rule.get("id", "")).strip() == str(rule_id).strip():
            return rule
    return None


def normalize_amount(value: Any) -> Any:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        cleaned = value.replace(",", "").strip()
        try:
            return float(cleaned)
        except Exception:
            return value
    return value


def extract_text_from_bytes(file_bytes: bytes, filename: str) -> str:
    ext = Path(filename).suffix.lower()

    if ext == ".pdf":
        if not _HAS_PDFPLUMBER:
            raise ImportError("pdfplumber is required for PDF extraction. pip install pdfplumber")
        text_parts: list[str] = []
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)
        return "\n".join(text_parts)

    if ext in (".docx", ".doc"):
        if not _HAS_DOCX:
            raise ImportError("python-docx is required for DOCX extraction. pip install python-docx")
        doc = DocxDocument(io.BytesIO(file_bytes))
        paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
        return "\n".join(paragraphs)

    if ext in (".txt", ".md", ""):
        return file_bytes.decode("utf-8", errors="replace")

    raise ValueError(f"Unsupported file type '{ext}'. Supported: .pdf, .docx, .txt, .md")


def structural_chunk(text: str, chunk_size: int = 300, overlap: int = 100) -> list[dict[str, Any]]:
    section_pattern = re.compile(
        r"(?=\n\s*(?:\d+\.\s|\bSection\s+\d+|\bPara\s+\d+|\bRule\s+\d+|\bClause\s+\d+))",
        re.IGNORECASE,
    )
    sections = section_pattern.split(text)

    sub_pattern = re.compile(
        r"(?=\n\s*(?:[a-z]\)|\([ivxlcdm]+\)|\•|\-\s))",
        re.IGNORECASE,
    )

    raw_segments: list[tuple[str, str]] = []
    for section in sections:
        section = section.strip()
        if not section:
            continue
        first_line = section.splitlines()[0].strip()
        label = first_line[:80] if first_line else "General"
        subs = sub_pattern.split(section)
        for sub in subs:
            sub = sub.strip()
            if len(sub) > 30:
                raw_segments.append((label, sub))

    chunks: list[dict[str, Any]] = []
    chunk_id = 0
    for section_label, segment in raw_segments:
        words = segment.split()
        if len(words) <= chunk_size:
            chunks.append(
                {
                    "chunk_id": chunk_id,
                    "section": section_label,
                    "text": segment,
                    "word_count": len(words),
                }
            )
            chunk_id += 1
        else:
            start = 0
            while start < len(words):
                end = min(start + chunk_size, len(words))
                chunk_text = " ".join(words[start:end])
                chunks.append(
                    {
                        "chunk_id": chunk_id,
                        "section": section_label,
                        "text": chunk_text,
                        "word_count": end - start,
                    }
                )
                chunk_id += 1
                start += chunk_size - overlap

    return chunks


def filter_compliance_chunks(chunks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    relevant: list[dict[str, Any]] = []
    for chunk in chunks:
        text_lower = chunk["text"].lower()
        if any(kw in text_lower for kw in COMPLIANCE_KEYWORDS):
            relevant.append(chunk)
    return relevant


_PARAM_EXTRACTION_PROMPT = """You are an AML compliance parameter extractor.

Extract ONLY the numeric threshold values defined in the regulation text below.
Return a JSON object with ONLY these keys (omit any key where the value is not
explicitly stated in the text):

  reporting_threshold      - maximum transaction amount before mandatory reporting (number in INR)
  structuring_txn_count    - minimum number of transactions to trigger structuring detection
  velocity_per_day         - maximum transactions per day threshold
  large_amount             - large value transaction amount threshold (number in INR)
  rapid_movement_days      - maximum days for rapid fund movement detection

RULES:
- Return ONLY a JSON object. No explanation. No markdown. No extra keys.
- Convert lakh/crore to INR numbers (1 lakh = 100000, 1 crore = 10000000).
- If a value is not stated in the text, do not include that key.
- Extract the EXACT numeric value stated. Do not average, estimate, or infer. If a value is stated as 'more than 30', extract 30. If stated as 'exceeding 30', extract 30.
- If you cannot find any values, return {{}}.

Regulation text:
{text}

Return JSON only, starting with {{"""


_RULE_TYPE_PROMPT = """You are an AML rule classifier.

Given this regulation text, identify which AML rule types it addresses.
Choose ONLY from this list:
  LARGE_TRANSACTION, STRUCTURING, HIGH_VELOCITY, JURISDICTION_RISK,
  RAPID_MOVEMENT, CRYPTO_EXPOSURE, PROFILE_MISMATCH, NEW_RULE

Return a JSON array of matching rule type strings. Nothing else.
If this regulation introduces a requirement that does not fit any existing
type, include NEW_RULE in the array.

Text:
{text}

Return JSON array only, starting with ["""


def _call_llm_json(prompt: str, model: str = DEFAULT_MODEL) -> Any:
    try:
        response = ollama.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.05, "num_ctx": 8192},
        )
        raw = response["message"]["content"].strip()

        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw).strip()

        start_obj = raw.find("{")
        start_arr = raw.find("[")
        start_brace = -1
        if start_obj != -1 and start_arr != -1:
            start_brace = min(start_obj, start_arr)
        elif start_obj != -1:
            start_brace = start_obj
        elif start_arr != -1:
            start_brace = start_arr

        if start_brace != -1:
            raw = raw[start_brace:]

        return json.loads(raw)
    except Exception as exc:
        return {"_error": str(exc)}


def extract_parameters_from_chunks(
    chunks: list[dict[str, Any]],
    model: str = DEFAULT_MODEL,
) -> dict[str, Any]:
    merged_params: dict[str, Any] = {}
    param_sources: dict[str, str] = {}

    batch_size = 1
    for i in range(0, len(chunks), batch_size):
        batch = chunks[i : i + batch_size]
        combined_text = "\n\n".join(c["text"] for c in batch)
        prompt = _PARAM_EXTRACTION_PROMPT.format(text=combined_text[:3000])
        result = _call_llm_json(prompt, model)
        if isinstance(result, dict) and "_error" not in result:
            for key, value in result.items():
                if key in THRESHOLD_KEYS:
                    try:
                        merged_params[key] = float(value)
                        param_sources[key] = batch[0]["section"]
                    except (ValueError, TypeError):
                        pass

    return {"extracted": merged_params, "sources": param_sources}


def extract_rule_types_from_chunks(
    chunks: list[dict[str, Any]],
    model: str = DEFAULT_MODEL,
) -> list[str]:
    combined = "\n\n".join(c["text"] for c in chunks[:10])
    prompt = _RULE_TYPE_PROMPT.format(text=combined[:3000])
    result = _call_llm_json(prompt, model)
    if isinstance(result, list):
        return [r for r in result if r in RULE_TYPE_LABELS]
    return []


def retrieve_relevant_regulation_context(
    query_keys: list[str],
    compliance_text: str,
    n_results: int = 5,
) -> list[str]:
    n_results = max(1, min(n_results, 10))

    if not query_keys:
        return []

    ordered_keys = sorted(set(query_keys))

    query_text = (
        "Regulation:\n"
        f"{(compliance_text or '').strip()[:4000]}\n\n"
        "Focus:\n"
        f"{' '.join(ordered_keys)}"
    )

    print(f"[RETRIEVAL QUERY] {query_text[:200]}")

    try:
        model = SentenceTransformer(EMBEDDING_MODEL)
        query_embeddings = model.encode([query_text], show_progress_bar=False).tolist()
        client = chromadb.PersistentClient(path=str(VECTOR_DB_PATH))
        collection = client.get_collection(REGULATION_COLLECTION_NAME)
        results = collection.query(query_embeddings=query_embeddings, n_results=n_results)
    except Exception as exc:
        print(f"[RETRIEVAL ERROR] {exc}")
        return []

    docs = results.get("documents") or []
    retrieved = docs[0] if docs and isinstance(docs[0], list) else []
    print(f"[RETRIEVED CHUNKS] {len(retrieved)}")

    deduped: list[str] = []
    seen_hashes: set[str] = set()
    for text in retrieved:
        if not isinstance(text, str):
            continue
        normalised = text.strip()
        if not normalised:
            continue
        digest = hashlib.sha256(normalised.encode("utf-8")).hexdigest()
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)
        deduped.append(normalised)
        if len(deduped) >= 10:
            break

    return deduped


def _load_current_thresholds() -> dict[str, Any]:
    ryaml = RuamelYAML()
    with RULES_YAML_PATH.open("r", encoding="utf-8") as f:
        config = ryaml.load(f)
    current = dict(config.get("thresholds", {}))
    if "high_risk_countries" in config:
        current["high_risk_countries"] = config.get("high_risk_countries")
    return current


def build_threshold_diff(
    extracted_params: dict[str, float],
    param_sources: dict[str, str],
) -> list[dict[str, Any]]:
    current = _load_current_thresholds()
    changes: list[dict[str, Any]] = []
    for key, new_val in extracted_params.items():
        old_val = current.get(key)
        changes.append(
            {
                "key": key,
                "description": THRESHOLD_KEYS.get(key, key),
                "old_value": old_val,
                "new_value": new_val,
                "is_change": old_val != new_val,
                "source_section": param_sources.get(key, "Unknown section"),
            }
        )
    return changes


def apply_threshold_updates(changes: list[dict[str, Any]]) -> dict[str, Any]:
    ryaml = RuamelYAML()
    ryaml.preserve_quotes = True

    with RULES_YAML_PATH.open("r", encoding="utf-8") as f:
        config = ryaml.load(f)

    if "thresholds" not in config:
        config["thresholds"] = {}

    applied: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for change in changes:
        if not change.get("is_change"):
            skipped.append(change)
            continue
        key = change["key"]
        new_val = change["new_value"]
        if key == "high_risk_countries":
            if isinstance(new_val, list):
                config["high_risk_countries"] = [str(v).strip() for v in new_val if str(v).strip()]
            else:
                skipped.append(change)
                continue
        else:
            if isinstance(new_val, (int, float)):
                config["thresholds"][key] = int(new_val) if float(new_val).is_integer() else float(new_val)
            else:
                skipped.append(change)
                continue
        applied.append(change)

    with RULES_YAML_PATH.open("w", encoding="utf-8") as f:
        ryaml.dump(config, f)

    return {
        "applied": applied,
        "skipped": skipped,
        "total_applied": len(applied),
    }


def build_gap_report(
    rule_types: list[str],
    compliance_chunks: list[dict[str, Any]],
    source_filename: str,
) -> dict[str, Any] | None:
    if "NEW_RULE" not in rule_types:
        return None

    new_rule_keywords = [
        "new",
        "additionally",
        "hereafter",
        "introduced",
        "added",
        "effective",
        "amended",
        "inserted",
        "substituted",
    ]
    gap_chunks = [
        c for c in compliance_chunks if any(kw in c["text"].lower() for kw in new_rule_keywords)
    ][:5]

    return {
        "type": "GAP_REPORT",
        "source_file": source_filename,
        "summary": (
            "This regulation contains requirements that cannot be handled "
            "by threshold parameter updates. New rule logic or new context "
            "paths may be required. Manual implementation by compliance tech "
            "team is needed before these requirements can be enforced."
        ),
        "relevant_chunks": [c["text"] for c in gap_chunks],
        "valid_context_paths": sorted(VALID_CONTEXT_PATHS),
        "action_required": (
            "Review the relevant chunks above. If a new VALID_CONTEXT_PATH "
            "is needed, add it to regulation_engine.py VALID_CONTEXT_PATHS "
            "and implement the corresponding context builder in rule_engine.py "
            "_build_context(). Then re-upload this regulation."
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def process_regulation_document(
    document_text: str,
    source_filename: str,
    model_name: str = DEFAULT_MODEL,
    file_bytes: bytes | None = None,
) -> dict[str, Any]:
    if file_bytes is not None:
        try:
            document_text = extract_text_from_bytes(file_bytes, source_filename)
        except Exception as exc:
            return {
                "success": False,
                "error": f"Text extraction failed: {exc}",
                "source_filename": source_filename,
            }

    if not document_text or len(document_text.strip()) < 50:
        return {
            "success": False,
            "error": "Document text is empty or too short to process.",
            "source_filename": source_filename,
        }

    all_chunks = structural_chunk(document_text)
    compliance_chunks = filter_compliance_chunks(all_chunks)

    if not compliance_chunks:
        return {
            "success": False,
            "error": (
                "No compliance-relevant content found in document. "
                "Ensure the document contains AML/regulatory threshold language."
            ),
            "total_chunks": len(all_chunks),
            "compliance_chunks": 0,
            "source_filename": source_filename,
        }

    query_keys = list(THRESHOLD_KEYS.keys()) + RULE_TYPE_LABELS
    compliance_text = "\n\n".join(c["text"] for c in compliance_chunks[:10])
    retrieved_chunks = retrieve_relevant_regulation_context(
        query_keys=query_keys,
        compliance_text=compliance_text,
        n_results=5,
    )

    combined_chunks = compliance_chunks + [
        {
            "text": txt,
            "section": "retrieved_context",
            "chunk_id": f"retrieved_{idx}",
            "word_count": len(txt.split()),
        }
        for idx, txt in enumerate(retrieved_chunks)
    ]

    deduped_chunks: list[dict[str, Any]] = []
    seen_chunk_hashes: set[str] = set()
    for chunk in combined_chunks:
        text = str(chunk.get("text") or "").strip()
        if not text:
            continue
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest in seen_chunk_hashes:
            continue
        seen_chunk_hashes.add(digest)
        deduped_chunks.append(chunk)

    # Extract threshold values strictly from the uploaded document content.
    # Retrieved context is useful for classification but can include stale limits.
    param_result = extract_parameters_from_chunks(compliance_chunks, model_name)
    extracted = param_result["extracted"]
    param_sources = param_result["sources"]

    rule_types = extract_rule_types_from_chunks(deduped_chunks, model_name)

    rules_config = load_rules_yaml()
    collection = _get_regulation_collection()
    llm = lambda prompt: _call_llm_json(prompt, model_name)

    updated_params: dict[str, Any] = {}

    known_countries = ["Syria", "SYRIA"]
    current_countries = rules_config.get("high_risk_countries", [])
    if any(country in document_text for country in known_countries):
        if "SYRIA" not in {str(c).upper() for c in current_countries}:
            updated_params["high_risk_countries"] = sorted(
                {str(c).upper() for c in current_countries if str(c).strip()} | {"SYRIA"}
            )

    for rule_type in rule_types:
        rule_ids = RULE_TYPE_TO_RULE_IDS.get(rule_type, [])

        for rule_id in rule_ids:
            rule_obj = find_rule_by_id(rules_config, rule_id)
            if not rule_obj:
                continue

            allowed_keys = RULE_TO_THRESHOLD_MAP.get(rule_type, [])
            if not allowed_keys:
                continue

            entities = extract_rule_entities(rule_obj)
            retrieved_for_rule = retrieve_rule_context(entities, collection)
            if not retrieved_for_rule:
                continue

            current_values: dict[str, Any] = {}
            for key in allowed_keys:
                if key == "high_risk_countries":
                    current_values[key] = rules_config.get("high_risk_countries", [])
                else:
                    current_values[key] = rules_config.get("thresholds", {}).get(key)

            raw = detect_threshold_change(
                llm,
                rule_obj,
                retrieved_for_rule,
                allowed_keys,
                current_values,
            )
            try:
                result = raw if isinstance(raw, dict) else json.loads(str(raw))
            except Exception:
                continue

            if not result.get("changed"):
                continue

            if not str(result.get("evidence", "")).strip():
                continue

            value: Any = normalize_amount(result.get("new_value"))
            selected_key = result.get("parameter")
            if selected_key is None and len(allowed_keys) == 1:
                selected_key = allowed_keys[0]
            if not isinstance(selected_key, str) or selected_key not in allowed_keys:
                continue

            for key in [selected_key]:
                if key not in THRESHOLD_KEYS:
                    continue

                if key == "high_risk_countries":
                    if isinstance(value, str):
                        value = [v.strip() for v in value.split(",") if v.strip()]
                    elif isinstance(value, list):
                        value = [str(v).strip() for v in value if str(v).strip()]
                    else:
                        continue

                    current_list = rules_config.get("high_risk_countries", [])
                    current_set = set(str(v).strip() for v in (current_list or []) if str(v).strip())
                    incoming_set = set(str(v).strip() for v in (value or []) if str(v).strip())
                    value = sorted(current_set.union(incoming_set))
                    current_value = sorted(current_set)
                else:
                    if not isinstance(value, (int, float)):
                        continue
                    value = float(value)
                    current_value = rules_config.get("thresholds", {}).get(key)
                    if isinstance(current_value, int):
                        current_value = float(current_value)

                if current_value == value:
                    continue

                if key not in updated_params:
                    updated_params[key] = value
                    if key not in param_sources:
                        param_sources[key] = "retrieved_context"

        print(f"[RULE UPDATE] {rule_type} -> {updated_params}")

    # Prefer values extracted from the uploaded regulation text itself.
    # Retrieved historical context can be stale and should not override direct document values.
    for key, extracted_value in extracted.items():
        if key not in THRESHOLD_KEYS or key == "high_risk_countries":
            continue
        if not isinstance(extracted_value, (int, float)):
            continue

        normalized_extracted = float(extracted_value)
        current_threshold = rules_config.get("thresholds", {}).get(key)
        if isinstance(current_threshold, int):
            current_threshold = float(current_threshold)

        if current_threshold == normalized_extracted:
            continue

        updated_params[key] = normalized_extracted
        param_sources[key] = param_sources.get(key, "document_extracted")

    # Normalize synonymous keys to avoid duplicate staging for the same threshold.
    # reporting_threshold and large_amount represent the same AML cash threshold in this pipeline.
    reporting_value = updated_params.get("reporting_threshold")
    if isinstance(reporting_value, (int, float)):
        normalized_reporting = float(reporting_value)
        if "large_amount" not in updated_params:
            current_large_amount = rules_config.get("thresholds", {}).get("large_amount")
            if isinstance(current_large_amount, int):
                current_large_amount = float(current_large_amount)
            if current_large_amount != normalized_reporting:
                updated_params["large_amount"] = normalized_reporting
                if "reporting_threshold" in param_sources:
                    param_sources["large_amount"] = param_sources["reporting_threshold"]

        updated_params.pop("reporting_threshold", None)
        param_sources.pop("reporting_threshold", None)

    threshold_changes = build_threshold_diff(updated_params, param_sources)
    actual_changes = [c for c in threshold_changes if c["is_change"]]
    gap_report = build_gap_report(rule_types, compliance_chunks, source_filename)
    doc_hash = hashlib.sha256(document_text.encode()).hexdigest()[:16]

    return {
        "success": True,
        "source_filename": source_filename,
        "doc_hash": doc_hash,
        "total_chunks": len(all_chunks),
        "compliance_chunks": len(compliance_chunks),
        "extracted_params": extracted,
        "param_sources": param_sources,
        "threshold_changes": threshold_changes,
        "actual_changes_count": len(actual_changes),
        "rule_types_detected": rule_types,
        "gap_report": gap_report,
        "ready_for_staging": len(actual_changes) > 0 or gap_report is not None,
        "compliance_chunk_texts": [c["text"] for c in compliance_chunks[:20]],
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }


def activate_asset_type_in_registry(
    asset_type: str,
    regulations: list[str],
    conclusion_regulation: str,
    additional_prompt_context: str,
    activated_by: str,
) -> None:
    try:
        registry = json.loads(REGULATION_REGISTRY_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        registry = {}

    registry[asset_type] = {
        "status": "ACTIVE",
        "rules_loaded": True,
        "rag_collection": "sar_knowledge" if asset_type.upper() == "FIAT_WIRE" else f"sar_knowledge_{asset_type.lower()}",
        "regulations": regulations,
        "conclusion_regulation": conclusion_regulation,
        "additional_prompt_context": additional_prompt_context,
        "activated_at": datetime.now(timezone.utc).isoformat(),
        "activated_by": activated_by,
    }

    REGULATION_REGISTRY_PATH.write_text(
        json.dumps(registry, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def get_registry() -> dict[str, Any]:
    try:
        return json.loads(REGULATION_REGISTRY_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


def check_regulatory_readiness(asset_type: str) -> dict[str, Any]:
    registry = get_registry()
    domain = registry.get(asset_type)

    if not domain:
        return {
            "ready": False,
            "status": "UNKNOWN_ASSET_TYPE",
            "missing": [
                f"No regulatory framework registered for asset type '{asset_type}'",
                "rules.yaml domain entry",
                "RAG knowledge base collection",
                "Regulation documents",
            ],
            "message": (
                f"Asset type '{asset_type}' has no registered regulatory framework. "
                f"Upload the governing regulation via the Rule Authoring Console."
            ),
        }

    if domain.get("status") != "ACTIVE":
        missing = []
        if not domain.get("rules_loaded"):
            missing.append("AML rules for this asset type")
        if not domain.get("rag_collection"):
            missing.append("RAG knowledge base collection")
        if not domain.get("regulations"):
            missing.append("Regulation documents")
        return {
            "ready": False,
            "status": "REGULATORY_FRAMEWORK_INCOMPLETE",
            "missing": missing,
            "message": (
                f"Asset type '{asset_type}' regulatory framework is not yet active. "
                f"Missing: {', '.join(missing)}."
            ),
        }

    return {
        "ready": True,
        "status": "ACTIVE",
        "missing": [],
        "message": "Regulatory framework active.",
        "domain_config": domain,
    }
