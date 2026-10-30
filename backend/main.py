import os
import secrets
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field


app = FastAPI(
    title="NEXORA ZENTIQ",
    description="Autonomous Security Intelligence Platform",
    version="0.1.0"
)

# Temporary storage.
# Supabase will provide permanent storage later.
events = []
alerts = []

INGEST_TOKEN = os.getenv("ZENTIQ_INGEST_TOKEN")


class SecurityEvent(BaseModel):
    source: str = Field(min_length=1, max_length=100)
    event_type: str = Field(min_length=1, max_length=100)
    severity: str = Field(default="medium")
    description: str = Field(default="", max_length=2000)
    timestamp: datetime | None = None
    metadata: dict = Field(default_factory=dict)


def analyse_event(event):
    score = 0

    severity_scores = {
        "low": 10,
        "medium": 30,
        "high": 65,
        "critical": 90
    }

    score += severity_scores.get(
        event.severity.lower(), 20
    )

    event_name = event.event_type.lower()

    suspicious_patterns = {
        "brute_force": 25,
        "malware": 35,
        "unauthorized_access": 35,
        "data_exfiltration": 40,
        "privilege_escalation": 30,
        "suspicious_login": 20
    }

    for pattern, points in suspicious_patterns.items():
        if pattern in event_name:
            score += points

    score = min(score, 100)

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_score": score,
        "risk_level": level
    }


@app.get("/")
def home():
    return {
        "platform": "NEXORA ZENTIQ",
        "status": "running",
        "version": "0.1.0"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/ingest")
def ingest_event(
    event: SecurityEvent,
    authorization: str | None = Header(default=None)
):
    if not INGEST_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="Ingestion authentication is not configured"
        )

    expected = f"Bearer {INGEST_TOKEN}"

    if not authorization or not secrets.compare_digest(
        authorization, expected
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication"
        )

    analysis = analyse_event(event)

    record = {
        "id": str(uuid4()),
        "source": event.source,
        "event_type": event.event_type,
        "description": event.description,
        "timestamp": (
            event.timestamp or datetime.now(timezone.utc)
        ).isoformat(),
        "risk_score": analysis["risk_score"],
        "risk_level": analysis["risk_level"],
        "metadata": event.metadata
    }

    events.append(record)

    if analysis["risk_level"] in ["HIGH", "CRITICAL"]:
        alerts.append(record)

    return {
        "message": "Security event received",
        "event": record
    }


@app.get("/analytics")
def analytics():
    return {
        "events_received": len(events),
        "alerts_generated": len(alerts),
        "risk_distribution": {
            level: sum(
                1 for event in events
                if event["risk_level"] == level
            )
            for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        }
  }
