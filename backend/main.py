import os
import secrets
from datetime import datetime, timezone
from uuid import uuid4
from statistics import mean, stdev

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from supabase import create_client


app = FastAPI(
    title="NEXORA ZENTIQ",
    description="Autonomous Security Intelligence Platform",
    version="0.2.0"
)

# Environment configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
INGEST_TOKEN = os.getenv("ZENTIQ_INGEST_TOKEN")

ANOMALY_THRESHOLD = float(
    os.getenv("ANOMALY_Z_THRESHOLD", "3.0")
)

# Database connection
db = None

if SUPABASE_URL and SUPABASE_KEY:
    db = create_client(SUPABASE_URL, SUPABASE_KEY)


class SecurityEvent(BaseModel):
    source: str = Field(min_length=1, max_length=150)
    event_type: str = Field(min_length=1, max_length=150)

    observed_at: datetime | None = None

    attributes: dict = Field(default_factory=dict)


def authenticate(token):

    if not INGEST_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="Ingestion authentication is not configured"
        )

    if not token or not secrets.compare_digest(
        token, INGEST_TOKEN
    ):
        raise HTTPException(
            status_code=401,
            detail="Authentication failed"
        )


def check_database():

    if db is None:
        raise HTTPException(
            status_code=503,
            detail="Database connection unavailable"
        )


def analyse_behaviour(event):

    check_database()

    # Retrieve historical events from the same source
    # and event category.

    history = (
        db.table("security_events")
        .select("attributes")
        .eq("source", event.source)
        .eq("event_type", event.event_type)
        .order("created_at", desc=True)
        .limit(100)
        .execute()
    )

    previous_events = history.data or []

    anomalies = []

    numeric_features = {
        key: value
        for key, value in event.attributes.items()
        if isinstance(value, (int, float))
        and not isinstance(value, bool)
    }

    for feature, current_value in numeric_features.items():

        historical_values = []

        for previous in previous_events:

            attributes = previous.get("attributes") or {}

            value = attributes.get(feature)

            if isinstance(value, (int, float)) and not isinstance(value, bool):
                historical_values.append(float(value))

        # Do not claim an anomaly without sufficient history.
        if len(historical_values) < 10:
            continue

        average = mean(historical_values)

        deviation = stdev(historical_values)

        if deviation == 0:
            continue

        z_score = abs(
            float(current_value) - average
        ) / deviation

        if z_score >= ANOMALY_THRESHOLD:

            anomalies.append({
                "feature": feature,
                "observed_value": current_value,
                "historical_average": round(average, 3),
                "deviation_score": round(z_score, 3)
            })

    return {
        "baseline_events": len(previous_events),
        "anomalies_detected": anomalies,
        "analysis_status": (
            "ANOMALY_DETECTED"
            if anomalies
            else "NO_ANOMALY_DETECTED"
            if len(previous_events) >= 10
            else "INSUFFICIENT_BASELINE"
        )
    }


@app.get("/")
def home():

    return {
        "platform": "NEXORA ZENTIQ",
        "status": "online",
        "version": "0.2.0"
    }


@app.get("/health")
def health():

    return {
        "api": "operational",
        "database": "connected" if db else "not_configured",
        "time": datetime.now(timezone.utc).isoformat()
    }


@app.post("/v1/events")
def receive_event(
    event: SecurityEvent,
    authorization: str | None = Header(default=None)
):

    check_database()

    authenticate(
        authorization.removeprefix("Bearer ").strip()
        if authorization
        else None
    )

    # Analyse against previously collected telemetry.
    analysis = analyse_behaviour(event)

    record = {
        "id": str(uuid4()),
        "source": event.source,
        "event_type": event.event_type,
        "observed_at": (
            event.observed_at or datetime.now(timezone.utc)
        ).isoformat(),
        "attributes": event.attributes,
        "analysis": analysis,
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    # Permanently store the event.
    result = (
        db.table("security_events")
        .insert(record)
        .execute()
    )

    return {
        "status": "received",
        "event": result.data[0] if result.data else record
    }


@app.get("/v1/status")
def system_status():

    check_database()

    result = (
        db.table("security_events")
        .select("id", count="exact")
        .execute()
    )

    return {
        "platform": "NEXORA ZENTIQ",
        "stored_events": result.count,
        "intelligence": "behavioural_baseline",
        "status": "operational"
    }
