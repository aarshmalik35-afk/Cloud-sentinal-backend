
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .scanner import scan_configuration

APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent
SAMPLE_DATA_DIR = ROOT_DIR / "sample_data"
SAMPLE_PATH = SAMPLE_DATA_DIR / "aws_config.json"

# Scenario JSON files are directly inside sample_data/
SCENARIO_FILES = {
    "secure": SAMPLE_DATA_DIR / "secure.json",
    "moderate_risk": SAMPLE_DATA_DIR / "moderate_risk.json",
    "high_risk": SAMPLE_DATA_DIR / "high_risk.json",
}

DB_PATH = Path(
    os.getenv(
        "CLOUDSENTINEL_DB_PATH",
        str(ROOT_DIR / "cloudsentinel_history.sqlite3"),
    )
)

app = FastAPI(
    title="CloudSentinel API",
    description=(
        "A defensive scanner for simulated AWS-style configuration data. "
        "It does not connect to live AWS accounts."
    ),
    version="2.1.0",
)

origins_raw = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,"
    "https://aarshmalik35-afk.github.io",
)

origins = [
    origin.strip().rstrip("/")
    for origin in origins_raw.split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    configuration: dict[str, Any] | None = Field(default=None)
    label: str | None = Field(default=None, max_length=120)
    scenario: str | None = Field(default=None)


def connect_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            scanned_at TEXT NOT NULL,
            label TEXT,
            payload TEXT NOT NULL
        )
    """)

    conn.commit()
    return conn


def save_scan(result: dict[str, Any], label: str | None = None):
    conn = connect_db()

    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO scans
            (scan_id, scanned_at, label, payload)
            VALUES (?, ?, ?, ?)
            """,
            (
                result["scan_id"],
                result["scanned_at"],
                label,
                json.dumps(result),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def load_scan(scan_id: str):
    conn = connect_db()

    try:
        row = conn.execute(
            "SELECT payload FROM scans WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()

        return json.loads(row["payload"]) if row else None
    finally:
        conn.close()


def load_json_configuration(path: Path, description: str):
    try:
        configuration = json.loads(
            path.read_text(encoding="utf-8")
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=500,
            detail=f"Missing {description} file: {path.name}",
        )
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Invalid JSON in {path.name}: {exc.msg}",
        )
    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not read {path.name}: {exc}",
        )

    if not isinstance(configuration, dict):
        raise HTTPException(
            status_code=500,
            detail=f"{path.name} must contain a JSON object",
        )

    return configuration


@app.get("/")
def root():
    return {
        "service": "CloudSentinel API",
        "status": "ok",
        "version": app.version,
        "scan_mode": "simulated_configuration",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "cloudsentinel-backend",
        "version": app.version,
    }


@app.get("/scenarios")
def get_scenarios():
    descriptions = {
        "secure": "A hardened environment with fewer expected findings.",
        "moderate_risk": "An environment with selected configuration weaknesses.",
        "high_risk": "A deliberately misconfigured environment.",
    }

    return {
        "scenarios": [
            {
                "id": scenario_id,
                "name": scenario_id.replace("_", " ").title(),
                "description": descriptions[scenario_id],
                "available": path.is_file(),
            }
            for scenario_id, path in SCENARIO_FILES.items()
        ]
    }


@app.post("/scan")
def scan(request: ScanRequest):
    # Custom configuration takes precedence over the selected scenario.
    if request.configuration is not None:
        configuration = request.configuration
        scenario_id = "custom"

    elif request.scenario is not None:
        scenario_id = request.scenario

        if scenario_id not in SCENARIO_FILES:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Unknown scenario '{scenario_id}'. "
                    f"Choose from: {', '.join(SCENARIO_FILES)}"
                ),
            )

        configuration = load_json_configuration(
            SCENARIO_FILES[scenario_id],
            f"scenario '{scenario_id}'",
        )

    else:
        scenario_id = "default"
        configuration = load_json_configuration(
            SAMPLE_PATH,
            "sample configuration",
        )

    result = scan_configuration(configuration)

    # Every scan gets a unique ID, even if the same scenario is scanned twice.
    result["scan_id"] = (
        f"{result['scan_id']}-{uuid.uuid4().hex[:8]}"
    )
    result["scenario"] = scenario_id
    result["label"] = (
        request.label
        or f"{scenario_id.replace('_', ' ').title()} scan"
    )

    save_scan(result, request.label)

    return result


@app.get("/history")
def history(limit: int = 20):
    limit = max(1, min(limit, 100))
    conn = connect_db()

    try:
        rows = conn.execute(
            """
            SELECT scan_id, scanned_at, label, payload
            FROM scans
            ORDER BY scanned_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        items = []

        for row in rows:
            payload = json.loads(row["payload"])

            items.append({
                "scan_id": row["scan_id"],
                "scanned_at": row["scanned_at"],
                "label": row["label"],
                "scenario": payload.get("scenario", "default"),
                "posture_score": payload.get("posture_score"),
                "risk_level": payload.get("risk_level"),
                "summary": payload.get("summary"),
            })

        return {
            "count": len(items),
            "history": items,
        }
    finally:
        conn.close()


@app.get("/history/{scan_id}")
def history_detail(scan_id: str):
    result = load_scan(scan_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return result


@app.get("/compare")
def compare(scan_id: str, against: str):
    current = load_scan(scan_id)
    previous = load_scan(against)

    if current is None or previous is None:
        raise HTTPException(
            status_code=404,
            detail="One or both scan IDs were not found in history",
        )

    current_keys = {
        (f["rule_id"], f["resource_id"]): f
        for f in current["findings"]
    }
    previous_keys = {
        (f["rule_id"], f["resource_id"]): f
        for f in previous["findings"]
    }

    new_keys = current_keys.keys() - previous_keys.keys()
    resolved_keys = previous_keys.keys() - current_keys.keys()
    unchanged_keys = current_keys.keys() & previous_keys.keys()

    return {
        "current_scan_id": scan_id,
        "previous_scan_id": against,
        "posture_score_change": (
            current["posture_score"] - previous["posture_score"]
        ),
        "new_findings": [
            current_keys[k] for k in sorted(new_keys)
        ],
        "resolved_findings": [
            previous_keys[k] for k in sorted(resolved_keys)
        ],
        "unchanged_findings": [
            current_keys[k] for k in sorted(unchanged_keys)
        ],
        "summary": {
            "new": len(new_keys),
            "resolved": len(resolved_keys),
            "unchanged": len(unchanged_keys),
        },
    }


@app.get("/report/{scan_id}")
def report(scan_id: str):
    result = load_scan(scan_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return {
        "report_type": "CloudSentinel security assessment",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": result,
    }
