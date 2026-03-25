from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any

import chromadb
from sentence_transformers import SentenceTransformer

VECTOR_DB_PATH = os.getenv("CHROMA_DB_PATH", "./vector_db")
DATA_FOLDER = os.getenv("DATA_FOLDER", "../data")
COLLECTION_NAME = "sar_knowledge"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# ---------------------------------------------------------------------------
# Document type detection — order matters, more specific patterns first
# ---------------------------------------------------------------------------
TYPE_PATTERNS: list[tuple[str, list[str]]] = [
    ("example",   ["EXAMPLE SAR", "filing institution is submitting", "filing institution submits",
                   "filing institution files", "has determined that the activity is suspicious"]),
    ("template",  ["TEMPLATE —", "{account_type}", "{customer_profile}", "{total_amount}",
                   "{transaction_count}", "{alert_type}"]),
    ("typology",  ["TYPOLOGY —", "FATF Reference", "Key indicators", "Regulatory significance",
                   "money laundering process", "placement stage"]),
    ("guideline", ["GUIDELINE —", "Approved opening sentences", "Approved closing sentences",
                   "Prohibited phrases", "APPROVED REGULATORY CITATIONS",
                   "Approved transaction description"]),
]


def detect_doc_type(text: str) -> str:
    for doc_type, signals in TYPE_PATTERNS:
        if any(signal in text for signal in signals):
            return doc_type
    return "general"


# ---------------------------------------------------------------------------
# Chunking strategies
# ---------------------------------------------------------------------------

def chunk_by_delimiter(text: str, delimiter: str = "\n---\n") -> list[str]:
    return [chunk.strip() for chunk in text.split(delimiter) if chunk.strip()]


def chunk_by_paragraph(text: str, min_words: int = 40) -> list[str]:
    paragraphs = [p.strip() for p in re.split(r"\n{2,}", text) if p.strip()]
    merged: list[str] = []
    buffer = ""
    for para in paragraphs:
        buffer = f"{buffer}\n\n{para}".strip() if buffer else para
        word_count = len(buffer.split())
        if word_count >= min_words:
            merged.append(buffer)
            buffer = ""
    if buffer:
        merged.append(buffer)
    return merged


def chunk_by_section_header(text: str) -> list[str]:
    """Split on lines that look like section headers (ALL CAPS or 'PARAGRAPH N —')."""
    header_pattern = re.compile(r"^(PARAGRAPH \d+|[A-Z][A-Z\s\-/]{8,})\s*$", re.MULTILINE)
    parts = header_pattern.split(text)
    chunks: list[str] = []
    i = 0
    while i < len(parts):
        part = parts[i].strip()
        if not part:
            i += 1
            continue
        if i + 1 < len(parts) and header_pattern.match(part):
            combined = f"{part}\n{parts[i+1].strip()}"
            if combined.strip():
                chunks.append(combined.strip())
            i += 2
        else:
            if part:
                chunks.append(part)
            i += 1
    return [c for c in chunks if len(c.split()) >= 20]


def smart_chunk(text: str, source_file: str) -> list[str]:
    """
    Choose chunking strategy based on file content and structure.

    - Files with \n---\n delimiters: primary split on delimiter,
      then paragraph-chunk any segment that is very long (>600 words).
    - All other files: paragraph chunking with a 40-word minimum.
    """
    if "\n---\n" in text:
        primary_chunks = chunk_by_delimiter(text, "\n---\n")
        final: list[str] = []
        for chunk in primary_chunks:
            if len(chunk.split()) > 600:
                final.extend(chunk_by_paragraph(chunk, min_words=60))
            else:
                final.append(chunk)
        return final
    return chunk_by_paragraph(text, min_words=40)


# ---------------------------------------------------------------------------
# Metadata enrichment
# ---------------------------------------------------------------------------

JURISDICTION_KEYWORDS = ["UAE", "CAYMAN", "PANAMA", "MAURITIUS", "SEYCHELLES",
                          "BAHAMAS", "VANUATU", "IRAN", "NORTH KOREA", "MYANMAR"]
TYPOLOGY_KEYWORDS = ["layering", "structuring", "smurfing", "round tripping",
                     "cash intensive", "velocity", "pass-through", "rapid fund movement",
                     "multi account", "profile inconsistency"]
REGULATION_KEYWORDS = ["PMLA", "RBI", "FIU-IND", "FATF", "KYC", "CTR", "STR"]


def enrich_metadata(chunk: str, source_file: str, doc_type: str, chunk_index: int) -> dict[str, Any]:
    lower = chunk.lower()
    return {
        "type": doc_type,
        "source": source_file,
        "chunk_index": chunk_index,
        "word_count": len(chunk.split()),
        "has_jurisdiction": any(kw in chunk.upper() for kw in JURISDICTION_KEYWORDS),
        "has_typology": any(kw in lower for kw in TYPOLOGY_KEYWORDS),
        "has_regulation": any(kw in chunk for kw in REGULATION_KEYWORDS),
        "is_example": doc_type == "example",
        "is_template": doc_type == "template",
    }


# ---------------------------------------------------------------------------
# Deduplication via content hash
# ---------------------------------------------------------------------------

def content_hash(text: str) -> str:
    return hashlib.sha256(text.strip().lower().encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Document loader
# ---------------------------------------------------------------------------

def load_documents(data_folder: str) -> tuple[list[str], list[dict[str, Any]], list[str]]:
    folder = Path(data_folder)
    all_chunks: list[str] = []
    all_metadata: list[dict[str, Any]] = []
    all_ids: list[str] = []
    seen_hashes: set[str] = set()

    txt_files = sorted(folder.glob("*.txt"))
    if not txt_files:
        print(f"WARNING: No .txt files found in {folder.resolve()}")
        return [], [], []

    for file_path in txt_files:
        print(f"  Loading: {file_path.name}")
        text = file_path.read_text(encoding="utf-8")
        chunks = smart_chunk(text, file_path.name)

        file_chunks = 0
        for chunk_index, chunk in enumerate(chunks):
            h = content_hash(chunk)
            if h in seen_hashes:
                continue
            seen_hashes.add(h)

            doc_type = detect_doc_type(chunk)
            metadata = enrich_metadata(chunk, file_path.name, doc_type, chunk_index)
            doc_id = f"{file_path.stem}_{chunk_index}_{h}"

            all_chunks.append(chunk)
            all_metadata.append(metadata)
            all_ids.append(doc_id)
            file_chunks += 1

        print(f"    -> {file_chunks} chunks (type distribution: "
              f"{_type_distribution(all_metadata[-file_chunks:] if file_chunks else [])})")

    return all_chunks, all_metadata, all_ids


def _type_distribution(metadatas: list[dict[str, Any]]) -> str:
    from collections import Counter
    counts = Counter(m["type"] for m in metadatas)
    return ", ".join(f"{t}:{n}" for t, n in counts.most_common())


# ---------------------------------------------------------------------------
# Main ingestion
# ---------------------------------------------------------------------------

def ingest(data_folder: str = DATA_FOLDER, vector_db_path: str = VECTOR_DB_PATH) -> None:
    print("\n=== SAR Knowledge Base Ingestion ===")
    print(f"Data folder : {Path(data_folder).resolve()}")
    print(f"Vector DB   : {Path(vector_db_path).resolve()}")

    print("\nLoading embedding model...")
    model = SentenceTransformer(EMBEDDING_MODEL)

    print("Connecting to ChromaDB...")
    client = chromadb.PersistentClient(path=str(vector_db_path))

    try:
        client.delete_collection(name=COLLECTION_NAME)
        print(f"Cleared existing collection '{COLLECTION_NAME}'.")
    except Exception:
        pass

    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"description": "SAR knowledge base — examples, typologies, guidelines, templates"},
    )

    print("\nLoading and chunking documents...")
    docs, metadatas, ids = load_documents(data_folder)

    if not docs:
        print("No documents loaded. Aborting.")
        return

    print(f"\nTotal chunks to embed: {len(docs)}")
    _print_type_summary(metadatas)

    print("\nGenerating embeddings...")
    BATCH_SIZE = 64
    all_embeddings: list[list[float]] = []
    for i in range(0, len(docs), BATCH_SIZE):
        batch = docs[i : i + BATCH_SIZE]
        batch_embeddings = model.encode(batch, show_progress_bar=False).tolist()
        all_embeddings.extend(batch_embeddings)
        print(f"  Embedded {min(i + BATCH_SIZE, len(docs))}/{len(docs)} chunks")

    print("\nStoring in ChromaDB...")
    UPSERT_BATCH = 100
    for i in range(0, len(docs), UPSERT_BATCH):
        collection.upsert(
            documents=docs[i : i + UPSERT_BATCH],
            embeddings=all_embeddings[i : i + UPSERT_BATCH],
            ids=ids[i : i + UPSERT_BATCH],
            metadatas=metadatas[i : i + UPSERT_BATCH],
        )

    final_count = collection.count()
    print(f"\nIngestion complete. Collection '{COLLECTION_NAME}' contains {final_count} documents.")
    _verify_retrieval(collection, model)


def _print_type_summary(metadatas: list[dict[str, Any]]) -> None:
    from collections import Counter
    counts = Counter(m["type"] for m in metadatas)
    print("\nDocument type breakdown:")
    for doc_type, count in counts.most_common():
        print(f"  {doc_type:<12} {count} chunks")
    print(f"  {'TOTAL':<12} {len(metadatas)} chunks")


def _verify_retrieval(collection: Any, model: SentenceTransformer) -> None:
    """Quick smoke test — run two representative queries and print top result."""
    print("\nVerification queries:")
    test_queries = [
        "layering via pass-through account UAE suspicious activity report",
        "structuring smurfing below threshold cash deposits",
    ]
    for query in test_queries:
        embedding = model.encode([query]).tolist()
        results = collection.query(query_embeddings=embedding, n_results=1)
        if results["documents"] and results["documents"][0]:
            top_doc = results["documents"][0][0]
            top_meta = results["metadatas"][0][0]
            score = round(1 - float(results["distances"][0][0]), 3)
            preview = top_doc[:120].replace("\n", " ")
            print(f"\n  Query : {query[:60]}...")
            print(f"  Match : [{top_meta['type']}] score={score} — \"{preview}...\"")
        else:
            print(f"  Query: {query} -> No results found")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Ingest SAR knowledge base into ChromaDB")
    parser.add_argument("--data", default=DATA_FOLDER, help="Path to data folder")
    parser.add_argument("--db", default=VECTOR_DB_PATH, help="Path to ChromaDB storage")
    args = parser.parse_args()

    ingest(data_folder=args.data, vector_db_path=args.db)