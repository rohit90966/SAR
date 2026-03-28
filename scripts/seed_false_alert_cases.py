from __future__ import annotations

"""
Seed two false-alert test cases by posting JSON payloads through the API.

This stores cases in DB via normal application flow (including false-alert filter).

Usage:
    python scripts/seed_false_alert_cases.py

Optional environment variables:
    FASTAPI_URL       (default: http://127.0.0.1:8000)
    API_USER          (default: analyst)
    API_PASSWORD      (default: password123)
"""

import json
import os
from pathlib import Path
from typing import Any
from urllib import error, request

from dotenv import load_dotenv

load_dotenv()

ROOT = Path(__file__).resolve().parent.parent
FALSE_ALERT_DIR = ROOT / "data" / "false_alert"

FASTAPI_URL = os.getenv("FASTAPI_URL", "http://127.0.0.1:8000").rstrip("/")
API_USER = os.getenv("API_USER", "analyst")
API_PASSWORD = os.getenv("API_PASSWORD", "password123")


def _http_json(method: str, path: str, payload: dict[str, Any] | None = None, token: str | None = None) -> tuple[int, dict[str, Any]]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = request.Request(f"{FASTAPI_URL}{path}", data=body, headers=headers, method=method)

    try:
        with request.urlopen(req, timeout=45) as resp:
            raw = resp.read().decode("utf-8")
            return resp.getcode(), (json.loads(raw) if raw else {})
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(raw)
        except Exception:
            return exc.code, {"detail": raw}


def _load_payload(file_name: str) -> dict[str, Any]:
    file_path = FALSE_ALERT_DIR / file_name
    with file_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def main() -> None:
    status, login = _http_json(
        "POST",
        "/login",
        payload={"username": API_USER, "password": API_PASSWORD},
    )
    if status != 200 or "access_token" not in login:
        raise RuntimeError(f"Login failed ({status}): {login}")

    token = str(login["access_token"])

    files = [
        "total_false_alert.json",
        "intermediate_false_alert.json",
    ]

    print(f"Seeding false-alert test cases into DB via {FASTAPI_URL}/cases")
    for file_name in files:
        payload = _load_payload(file_name)
        status, resp = _http_json("POST", "/cases", payload=payload, token=token)
        print(
            json.dumps(
                {
                    "file": file_name,
                    "http_status": status,
                    "case_id": resp.get("case_id"),
                    "status": resp.get("status"),
                    "verdict": resp.get("verdict"),
                    "true_positive_score": resp.get("true_positive_score"),
                    "detail": resp.get("detail"),
                },
                ensure_ascii=False,
            )
        )


if __name__ == "__main__":
    main()
