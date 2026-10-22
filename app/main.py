from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .scanner import scan_configuration

APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent
SAMPLE_DIR = ROOT_DIR / "sample_data"
SAMPLE_PATH = SAMPLE_DIR / "aws_config.json"
SCENARIO_DIR = SAMPLE_DIR / "scenarios"
DB_PATH = Path(os.getenv("CLOUDSENTINEL_DB_PATH", str(ROOT_DIR / "cloudsentinel_history.sqlite3")))

SCENARIOS: dict[str, dict[str, str]] = {
    "secure": {"label": "Secure environment", "description": "Hardened simulated configuration with encryption, public access blocks, least-privilege IAM, and audit logging."},
    "moderate_risk": {"label": "Moderate risk", "description": "A mostly configured environment with selected resilience and monitoring gaps."},
    "high_risk": {"label": "High risk", "description": "Intentionally vulnerable demo configuration including public storage, broad IAM, exposed remote access, and logging gaps."},
}

app = FastAPI(title="CloudSentinel API", description="A defensive scanner for simulated AWS-style configuration data. It does not connect to live AWS accounts.", version="2.1.0")
origins_raw = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,https://aarshmalik35-afk.github.io")
origins = [origin.strip().rstrip("/") for origin in origins_raw.split(",") if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["*"])

class ScanRequest(BaseModel):
    scenario: Literal["secure", "moderate_risk", "high_risk"] | None = Field(default=None, description="Named bundled simulated scenario.")
    configuration: dict[str, Any] | None = Field(default=None, description="Optional custom configuration; takes precedence over scenario.")
    label: str | None = Field(default=None, max_length=120)

def connect_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE IF NOT EXISTS scans (scan_id TEXT PRIMARY KEY, scanned_at TEXT NOT NULL, label TEXT, payload TEXT NOT NULL)")
    conn.commit()
    return conn

def save_scan(result: dict[str, Any], label: str | None = None):
    conn = connect_db()
    try:
        conn.execute("INSERT OR REPLACE INTO scans(scan_id, scanned_at, label, payload) VALUES (?, ?, ?, ?)", (result["scan_id"], result["scanned_at"], label, json.dumps(result)))
        conn.commit()
    finally:
        conn.close()

def load_scan(scan_id: str):
    conn = connect_db()
    try:
        row = conn.execute("SELECT payload FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        return json.loads(row["payload"]) if row else None
    finally:
        conn.close()

def load_scenario(scenario: str) -> dict[str, Any]:
    if scenario not in SCENARIOS:
        raise HTTPException(status_code=422, detail=f"Unknown scenario '{scenario}'. Use one of: {', '.join(SCENARIOS)}")
    path = SCENARIO_DIR / f"{scenario}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=f"Could not load scenario '{scenario}': {exc}") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=500, detail=f"Scenario '{scenario}' must contain a JSON object")
    return data

@app.get("/")
def root():
    return {"service": "CloudSentinel API", "status": "ok", "version": "2.1.0", "scan_mode": "simulated_configuration", "docs": "/docs"}

@app.get("/health")
def health():
    return {"status": "ok", "service": "cloudsentinel-backend", "version": "2.1.0"}

@app.get("/scenarios")
def list_scenarios():
    return {"scenarios": [{"id": key, **value} for key, value in SCENARIOS.items()]}

@app.post("/scan")
def scan(request: ScanRequest):
    configuration = request.configuration
    scenario_id = None
    if configuration is None and request.scenario:
        configuration = load_scenario(request.scenario)
        scenario_id = request.scenario
    elif configuration is None:
        try:
            configuration = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
            scenario_id = "high_risk"
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=500, detail=f"Could not load sample configuration: {exc}") from exc
    if not isinstance(configuration, dict):
        raise HTTPException(status_code=422, detail="configuration must be a JSON object")
    result = scan_configuration(configuration)
    result["scenario"] = scenario_id or "custom"
    result["scenario_label"] = SCENARIOS.get(scenario_id, {}).get("label", "Custom configuration")
    result["configuration"] = configuration
    label = request.label or result["scenario_label"]
    save_scan(result, label)
    return result

@app.get("/history")
def history(limit: int = 20):
    limit = max(1, min(limit, 100))
    conn = connect_db()
    try:
        rows = conn.execute("SELECT scan_id, scanned_at, label, payload FROM scans ORDER BY scanned_at DESC LIMIT ?", (limit,)).fetchall()
        items = []
        for row in rows:
            payload = json.loads(row["payload"])
            items.append({"scan_id": row["scan_id"], "scanned_at": row["scanned_at"], "label": row["label"], "posture_score": payload.get("posture_score"), "risk_level": payload.get("risk_level"), "scenario": payload.get("scenario"), "scenario_label": payload.get("scenario_label"), "summary": payload.get("summary")})
        return {"count": len(items), "history": items}
    finally:
        conn.close()

@app.get("/history/{scan_id}")
def history_detail(scan_id: str):
    result = load_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result

@app.get("/compare")
def compare(scan_id: str, against: str):
    current, previous = load_scan(scan_id), load_scan(against)
    if current is None or previous is None:
        raise HTTPException(status_code=404, detail="One or both scan IDs were not found in history")
    current_keys = {(f["rule_id"], f["resource_id"]): f for f in current["findings"]}
    previous_keys = {(f["rule_id"], f["resource_id"]): f for f in previous["findings"]}
    new_keys, resolved_keys = current_keys.keys() - previous_keys.keys(), previous_keys.keys() - current_keys.keys()
    unchanged_keys = current_keys.keys() & previous_keys.keys()
    return {"current_scan_id": scan_id, "previous_scan_id": against, "posture_score_change": current["posture_score"] - previous["posture_score"], "new_findings": [current_keys[k] for k in sorted(new_keys)], "resolved_findings": [previous_keys[k] for k in sorted(resolved_keys)], "unchanged_findings": [current_keys[k] for k in sorted(unchanged_keys)], "summary": {"new": len(new_keys), "resolved": len(resolved_keys), "unchanged": len(unchanged_keys)}}

@app.get("/report/{scan_id}")
def report(scan_id: str):
    result = load_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"report_type": "CloudSentinel security assessment", "generated_at": datetime.now(timezone.utc).isoformat(), "scan": result}
