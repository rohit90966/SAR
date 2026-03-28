from __future__ import annotations

import hashlib
import io
import os
import re
from pathlib import Path
from typing import Any

import chromadb
from sentence_transformers import SentenceTransformer

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

VECTOR_DB_PATH = os.getenv("CHROMA_DB_PATH", "./vector_db")
DATA_FOLDER = os.getenv("DATA_FOLDER", "../data")
SHARED_COLLECTION_NAME = "sar_knowledge_all"
LEGACY_COLLECTION_NAME = "sar_knowledge"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

TYPE_PATTERNS: list[tuple[str, list[str]]] = [
    ("example",   ["EXAMPLE SAR", "filing institution is submitting",
                   "filing institution submits", "filing institution files",
                   "has determined that the activity is suspicious"]),
    ("template",  ["TEMPLATE —", "{account_type}", "{customer_profile}",
                   "{total_amount}", "{transaction_count}", "{alert_type}"]),
    ("typology",  ["TYPOLOGY —", "FATF Reference", "Key indicators",
                   "Regulatory significance", "money laundering process",
                   "placement stage"]),
    ("guideline", ["GUIDELINE —", "Approved opening sentences",
                   "Approved closing sentences", "Prohibited phrases",
                   "APPROVED REGULATORY CITATIONS",
                   "Approved transaction description"]),
    ("regulation", ["ASSET_TYPE:", "REGULATION_NAME:", "ISSUING_AUTHORITY:",
                    "THRESHOLDS:", "REGULATORY_CITATIONS:",
                    "CONCLUSION_REGULATION_TEXT:"]),
]


def detect_doc_type(text: str) -> str:
    for doc_type, signals in TYPE_PATTERNS:
        if any(signal in text for signal in signals):
            return doc_type
    return "general"


def chunk_by_delimiter(text: str, delimiter: str = "\n---\n") -> list[str]:
    return [c.strip() for c in text.split(delimiter) if c.strip()]


def chunk_by_paragraph(text: str, min_words: int = 40) -> list[str]:
    paragraphs = [p.strip() for p in re.split(r"\n{2,}", text) if p.strip()]
    merged: list[str] = []
    buffer = ""
    for para in paragraphs:
        buffer = f"{buffer}\n\n{para}".strip() if buffer else para
        if len(buffer.split()) >= min_words:
            merged.append(buffer)
            buffer = ""
    if buffer:
        merged.append(buffer)
    return merged


def smart_chunk(text: str, source_file: str) -> list[str]:
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


JURISDICTION_KEYWORDS = [
    "UAE", "CAYMAN", "PANAMA", "MAURITIUS", "SEYCHELLES",
    "BAHAMAS", "VANUATU", "IRAN", "NORTH KOREA", "MYANMAR",
]
TYPOLOGY_KEYWORDS = [
    "layering", "structuring", "smurfing", "round tripping",
    "cash intensive", "velocity", "pass-through", "rapid fund movement",
    "multi account", "profile inconsistency",
    "crypto", "virtual digital asset", "vda", "unhosted wallet",
    "on-chain", "mixer", "defi",
]
REGULATION_KEYWORDS = [
    "PMLA", "RBI", "FIU-IND", "FATF", "KYC", "CTR", "STR",
    "VDA", "VASP", "crypto",
]


def enrich_metadata(
    chunk: str,
    source_file: str,
    doc_type: str,
    chunk_index: int,
    domain: str = "ALL",
) -> dict[str, Any]:
    lower = chunk.lower()
    return {
        "type": doc_type,
        "source": source_file,
        "chunk_index": chunk_index,
        "domain": domain,
        "word_count": len(chunk.split()),
        "has_jurisdiction": any(kw in chunk.upper() for kw in JURISDICTION_KEYWORDS),
        "has_typology": any(kw in lower for kw in TYPOLOGY_KEYWORDS),
        "has_regulation": any(kw in chunk for kw in REGULATION_KEYWORDS),
        "is_example": doc_type == "example",
        "is_template": doc_type == "template",
    }


def content_hash(text: str) -> str:
    return hashlib.sha256(
        text.strip().lower().encode("utf-8")
    ).hexdigest()[:16]


def load_documents(
    data_folder: str,
    domain: str = "ALL",
) -> tuple[list[str], list[dict[str, Any]], list[str]]:
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
            metadata = enrich_metadata(
                chunk, file_path.name, doc_type, chunk_index, domain
            )
            doc_id = f"{domain}_{file_path.stem}_{chunk_index}_{h}"

            all_chunks.append(chunk)
            all_metadata.append(metadata)
            all_ids.append(doc_id)
            file_chunks += 1

        print(f"    -> {file_chunks} chunks")

    return all_chunks, all_metadata, all_ids


def ingest_regulation_document(
    document_text: str,
    asset_type: str,
    source_filename: str,
    regulation_name: str = "",
    vector_db_path: str = VECTOR_DB_PATH,
) -> dict[str, Any]:
    """
    Ingest a single regulation document into the domain-specific
    ChromaDB collection. Called after compliance officer approves
    the regulation via the Rule Authoring Console.
    """
    print(f"\nIngesting regulation document for domain: {asset_type}")
    model = SentenceTransformer(EMBEDDING_MODEL)
    client = chromadb.PersistentClient(path=str(vector_db_path))

    if asset_type.upper() == "FIAT_WIRE":
        collection_name = LEGACY_COLLECTION_NAME
    else:
        collection_name = f"sar_knowledge_{asset_type.lower()}"
    collection = client.get_or_create_collection(
        name=collection_name,
        metadata={
            "description": f"SAR knowledge base for {asset_type} domain",
            "domain": asset_type,
        },
    )

    chunks = smart_chunk(document_text, source_filename)
    seen_hashes: set[str] = set()
    docs: list[str] = []
    metadatas: list[dict[str, Any]] = []
    ids: list[str] = []

    for chunk_index, chunk in enumerate(chunks):
        h = content_hash(chunk)
        if h in seen_hashes:
            continue
        seen_hashes.add(h)

        doc_type = detect_doc_type(chunk)
        metadata = enrich_metadata(
            chunk, source_filename, doc_type, chunk_index, asset_type
        )
        doc_id = f"{asset_type.lower()}_{source_filename}_{chunk_index}_{h}"
        metadata["regulation_name"] = regulation_name

        docs.append(chunk)
        metadatas.append(metadata)
        ids.append(doc_id)

    if not docs:
        return {
            "success": False,
            "reason": "No chunks extracted from document.",
            "collection": collection_name,
        }

    embeddings = model.encode(docs, show_progress_bar=False).tolist()

    collection.upsert(
        documents=docs,
        embeddings=embeddings,
        ids=ids,
        metadatas=metadatas,
    )

    print(f"Ingested {len(docs)} chunks into collection '{collection_name}'")
    return {
        "success": True,
        "collection": collection_name,
        "chunks_ingested": len(docs),
        "asset_type": asset_type,
    }


def extract_text_from_file_bytes(file_bytes: bytes, filename: str) -> str:
    ext = Path(filename).suffix.lower()

    if ext == ".pdf":
        if not _HAS_PDFPLUMBER:
            raise ImportError("pdfplumber is required for PDF extraction")
        text_parts: list[str] = []
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)
        return "\n".join(text_parts)

    if ext in (".docx", ".doc"):
        if not _HAS_DOCX:
            raise ImportError("python-docx is required for DOCX extraction")
        doc = DocxDocument(io.BytesIO(file_bytes))
        return "\n".join(p.text for p in doc.paragraphs if p.text and p.text.strip())

    if ext in (".txt", ".md", ""):
        return file_bytes.decode("utf-8", errors="replace")

    raise ValueError(f"Unsupported file type: {ext}")


def ingest_regulation_file_bytes(
    file_bytes: bytes,
    filename: str,
    asset_type: str,
    regulation_name: str = "",
    vector_db_path: str = VECTOR_DB_PATH,
) -> dict[str, Any]:
    text = extract_text_from_file_bytes(file_bytes, filename)
    return ingest_regulation_document(
        document_text=text,
        asset_type=asset_type,
        source_filename=filename,
        regulation_name=regulation_name or filename,
        vector_db_path=vector_db_path,
    )


def ingest(
    data_folder: str = DATA_FOLDER,
    vector_db_path: str = VECTOR_DB_PATH,
) -> None:
    """
    Main ingestion — runs at startup.
    Ingests all .txt files from data/ into:
      - sar_knowledge_all  (shared collection, domain=ALL)
      - sar_knowledge      (legacy collection for backward compatibility)
    """
    print("\n=== SAR Knowledge Base Ingestion ===")
    print(f"Data folder : {Path(data_folder).resolve()}")
    print(f"Vector DB   : {Path(vector_db_path).resolve()}")

    print("\nLoading embedding model...")
    model = SentenceTransformer(EMBEDDING_MODEL)

    print("Connecting to ChromaDB...")
    client = chromadb.PersistentClient(path=str(vector_db_path))

    for col_name in [SHARED_COLLECTION_NAME, LEGACY_COLLECTION_NAME]:
        try:
            client.delete_collection(name=col_name)
            print(f"Cleared existing collection '{col_name}'.")
        except Exception:
            pass

    shared_collection = client.get_or_create_collection(
        name=SHARED_COLLECTION_NAME,
        metadata={"description": "Shared SAR knowledge — all domains"},
    )
    legacy_collection = client.get_or_create_collection(
        name=LEGACY_COLLECTION_NAME,
        metadata={"description": "Legacy SAR knowledge base"},
    )

    print("\nLoading and chunking documents...")
    docs, metadatas, ids = load_documents(data_folder, domain="ALL")

    if not docs:
        print("No documents loaded. Aborting.")
        return

    print(f"\nTotal chunks: {len(docs)}")

    print("\nGenerating embeddings...")
    BATCH_SIZE = 64
    all_embeddings: list[list[float]] = []
    for i in range(0, len(docs), BATCH_SIZE):
        batch = docs[i: i + BATCH_SIZE]
        batch_embeddings = model.encode(
            batch, show_progress_bar=False
        ).tolist()
        all_embeddings.extend(batch_embeddings)

    print("\nStoring in ChromaDB...")
    UPSERT_BATCH = 100
    for i in range(0, len(docs), UPSERT_BATCH):
        shared_collection.upsert(
            documents=docs[i: i + UPSERT_BATCH],
            embeddings=all_embeddings[i: i + UPSERT_BATCH],
            ids=ids[i: i + UPSERT_BATCH],
            metadatas=metadatas[i: i + UPSERT_BATCH],
        )
        legacy_collection.upsert(
            documents=docs[i: i + UPSERT_BATCH],
            embeddings=all_embeddings[i: i + UPSERT_BATCH],
            ids=ids[i: i + UPSERT_BATCH],
            metadatas=metadatas[i: i + UPSERT_BATCH],
        )

    print(
        f"\nIngestion complete. "
        f"'{SHARED_COLLECTION_NAME}' contains {shared_collection.count()} documents."
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Ingest SAR knowledge base into ChromaDB"
    )
    parser.add_argument("--data", default=DATA_FOLDER)
    parser.add_argument("--db", default=VECTOR_DB_PATH)
    args = parser.parse_args()
    ingest(data_folder=args.data, vector_db_path=args.db)