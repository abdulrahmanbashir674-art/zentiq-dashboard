from datetime import datetime, timezone
from collections import Counter
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional


app = FastAPI(
    title="NEXORA ZENTIQ Intelligence Engine",
    description="Autonomous security event processing API",
    version="0.1.0"
)


# Temporary storage for development.
# We will replace this with a database later.
events = []


class SecurityEvent(BaseModel):
    source: str = Field(min_length=2, max_length=100)
    event_type: str = Field(min_length=2, max_length=100)
    description: str = Field(min_length=2, max_length=1000)

    failed_attempts: int = Field(default=0, ge=0, le=10000)
    unusual_activity: bool = False
    severity: Optional[str] = None


def analyse_event(event: SecurityEvent):

    score = 0
    reasons = []

    if event.failed_attempts >= 10:
        score += 40
        reasons.append("High number of failed attempts")

    elif event.failed_attempts >= 5:
        score += 20
        reasons.append("Repeated failed attempts")

    if event.unusual_activity:
        score += 30
        reasons.append("Unusual activity reported")

    if event.severity == "critical":
        score += 40
        reasons.append("Critical severity reported")

    elif event.severity == "high":
        score += 25
        reasons.append("High severity reported")

    score = min(score, 100)

    if score >= 75:
        risk = "CRITICAL"

    elif score >= 50:
        risk = "HIGH"

    elif score >= 25:
        risk = "MEDIUM"

    else:
        risk = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk,
        "reasons": reasons
    }


@app.get("/")
def home():
    return {
        "platform": "NEXORA ZENTIQ",
        "engine": "Intelligence Engine",
        "version": "0.1.0",
        "status": "Running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/events")
def receive_event(event: SecurityEvent):

    analysis = analyse_event(event)

    record = {
        "id": str(uuid4()),
        "received_at": datetime.now(timezone.utc).isoformat(),
        "source": event.source,
        "event_type": event.event_type,
        "description": event.description,
        **analysis
    }

    events.append(record)

    return {
        "message": "Event processed successfully",
        "event": record
    }


@app.get("/events")
def get_events():

    return {
        "total": len(events),
        "events": events
    }


@app.get("/analytics")
def analytics():

    risk_counts = Counter(
        event["risk_level"] for event in events
    )

    return {
        "total_events": len(events),
        "critical": risk_counts["CRITICAL"],
        "high": risk_counts["HIGH"],
        "medium": risk_counts["MEDIUM"],
        "low": risk_counts["LOW"]
  }
