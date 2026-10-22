from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.scanner import scan_configuration

APP_DIR = Path(__file__).resolve().parent
SAMPLE_DATA = APP_DIR.parent / "sample_data" / "aws_config.json"

app = FastAPI(
    title="CloudSentinel API",
    description="A defensive AWS configuration security scanner. The demo scans supplied configuration data; it does not connect to AWS.",
    version="0.1.0",
)

# Set CORS_ORIGINS to a comma-separated list of trusted frontend origins in production.
# For local development, localhost origins are allowed.
cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


class ScanRequest(BaseModel):
    configuration: dict[str, Any] | None = Field(
        default=None,
        description="Optional AWS-style configuration object. If omitted, the bundled demo configuration is scanned.",
    )


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "CloudSentinel API",
        "version": "0.1.0",
        "docs": "/docs",
        "note": "Demo mode: scans sample configuration; no AWS account connection is made.",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan")
def scan(request: ScanRequest) -> dict[str, Any]:
    configuration = request.configuration
    if configuration is None:
        try:
            configuration = json.loads(SAMPLE_DATA.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=500,
                detail="Bundled sample configuration could not be loaded.",
            ) from exc

    try:
        return scan_configuration(configuration)
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid configuration: {exc}") from exc
