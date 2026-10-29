
"""
Event & Threat Ingestion Endpoints (/api/events)

Pipeline:
Security Event -> Server-side ML Scoring -> Response Policy
-> Database Audit -> SOC WebSocket

External HTTP ingestion requires a configured sensor API key.
Internal backend calls may invoke ingest_security_event directly.
"""

import json
import os
import secrets
import uuid
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.models.event import SecurityEvent
from backend.app.models.threat import ThreatRecord
from backend.app.models.audit import AuditLog
from backend.app.schemas.event import EventIngestRequest
from backend.app.schemas.threat import (
    CombinedThreatIngestResponse,
    ThreatRecordOut,
)
from backend.app.services.ml_service import MLService
from backend.app.services.cloud_service import cloud_service
from backend.app.services.geoip_service import get_geo_for_ip
from backend.app.core.websocket import soc_ws_manager

logger = logging.getLogger("SentinelAI.EventIngestion")

router = APIRouter(
    prefix="/events",
    tags=["Event Ingestion & Processing"],
)


def require_sensor_api_key(
    x_sensor_api_key: str | None = Header(
        default=None,
        alias="X-SentinelAI-Sensor-Key",
    ),
) -> None:
    """
    Authenticate external sensor requests.

    Configure SENTINELAI_SENSOR_API_KEY in the backend environment.
    If it is missing, external ingestion is denied.
    Never put this key in React/browser code.
    """
    expected_key = os.getenv("SENTINELAI_SENSOR_API_KEY")

    if not expected_key:
        logger.error(
            "SENTINELAI_SENSOR_API_KEY is not configured; "
            "external event ingestion is disabled."
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Event ingestion is not configured.",
        )

    if (
        not x_sensor_api_key
        or not secrets.compare_digest(x_sensor_api_key, expected_key)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing sensor credentials.",
        )


def _get_event_status(event_type: str, ml_result: dict, audit_entry) -> str:
    """Report event outcome separately from response enforcement."""
    event_type_upper = str(event_type or "").upper()

    if (
        event_type_upper in {"LOGIN_FAILED", "AUTH_FAILED"}
        or event_type_upper.endswith("_LOGIN_FAILED")
    ):
        return "Failed"

    if audit_entry.action == "BLOCK":
        return "Detected" if audit_entry.dry_run else "Blocked"

    if ml_result.get("prediction") == -1:
        return "Detected"

    return "Success"


@router.post(
    "/ingest",
    response_model=CombinedThreatIngestResponse,
    dependencies=[Depends(require_sensor_api_key)],
)
def ingest_security_event(
    request: EventIngestRequest,
    db: Session = Depends(get_db),
):
    """
    Process a security event.

    External HTTP calls must pass the sensor API-key dependency.
    Internal Python calls to this function do not run FastAPI dependencies;
    they must only be made by trusted backend code.
    """
    event_uuid = f"EVT-{uuid.uuid4().hex[:8].upper()}"
    now_utc = datetime.now(timezone.utc)

    # Copy caller-supplied details so we never mutate the request object.
    details = dict(request.details or {})

    # Never accept a caller-supplied score as the ML decision.
    # The model and server-side rules must calculate risk independently.
    details.pop("risk_score", None)

    # Enrich the source IP.
    raw_ip = request.source_ip or "0.0.0.0"
    geo = get_geo_for_ip(raw_ip)

    resolved_city = request.source_city or geo["city"]
    resolved_country = request.source_country or geo["country"]
    resolved_region = request.source_region or geo["region"]

    resolved_lat = (
        request.source_lat
        if request.source_lat is not None
        else geo["lat"]
    )
    resolved_lng = (
        request.source_lng
        if request.source_lng is not None
        else geo["lng"]
    )

    if resolved_city not in ("Unknown", "Private Network"):
        resolved_location_str = f"{resolved_city}, {resolved_country}"
    else:
        resolved_location_str = geo["geo_source"].upper()

    # IMPORTANT: do not pass custom_risk_score from the request.
    ml_result = MLService.evaluate_event(
        event_type=request.event_type,
        details=details,
    )

    # Apply the existing response policy.
    # Real blocking is only possible if the response engine enforces it.
    audit_entry = cloud_service.process_threat_telemetry(
        event_id=event_uuid,
        source_ip=raw_ip,
        risk_score=ml_result["risk_score"],
        threat_type=request.event_type,
        user_id=request.user_id,
        location=resolved_location_str,
        is_anomalous=(ml_result["prediction"] == -1),
        details=details,
    )

    event_status = _get_event_status(
        request.event_type,
        ml_result,
        audit_entry,
    )

    db_event = SecurityEvent(
        event_id=event_uuid,
        event_type=request.event_type,
        user_id=request.user_id,
        source_ip=raw_ip,
        device=request.device or "Windows PC",
        browser=request.browser or "Unknown",
        location=resolved_location_str,
        status=event_status,
        risk_score=ml_result["risk_score"],
        risk_level=ml_result["risk_level"],
        timestamp=now_utc,
    )

    db_threat = ThreatRecord(
        event_id=event_uuid,
        source_ip=raw_ip,
        source_country=resolved_country,
        source_region=resolved_region,
        source_city=resolved_city,
        source_lat=resolved_lat,
        source_lng=resolved_lng,
        target_city=request.target_city or "Bengaluru",
        attack_type=request.event_type,
        user_id=request.user_id,
        device=request.device,
        browser=request.browser,
        prediction=ml_result["prediction"],
        threat_status=ml_result["threat"],
        anomaly_score=ml_result["anomaly_score"],
        risk_score=ml_result["risk_score"],
        risk_level=ml_result["risk_level"],
        is_anomalous=(ml_result["prediction"] == -1),
        response_status=(
            "BLOCKED_SIMULATED"
            if audit_entry.action == "BLOCK" and audit_entry.dry_run
            else audit_entry.action
        ),
        policy_applied=audit_entry.policy_applied,
        timestamp=now_utc,
    )

    db_audit = AuditLog(
        log_id=audit_entry.log_id,
        timestamp=audit_entry.timestamp,
        event_id=event_uuid,
        source_ip=audit_entry.source_ip,
        risk_score=audit_entry.risk_score,
        action=audit_entry.action,
        policy_applied=audit_entry.policy_applied,
        dry_run=audit_entry.dry_run,
        summary=audit_entry.summary,
        metadata_json=json.dumps(audit_entry.metadata),
    )

    # Commit the three database records together.
    try:
        db.add_all([db_event, db_threat, db_audit])
        db.commit()
        db.refresh(db_threat)
    except Exception as exc:
        db.rollback()
        logger.exception("Failed to persist event %s", event_uuid)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist the security event.",
        ) from exc

    threat_out = ThreatRecordOut(
        id=db_threat.id,
        event_id=db_threat.event_id,
        source_ip=db_threat.source_ip,
        source_country=db_threat.source_country,
        source_region=db_threat.source_region,
        source_city=db_threat.source_city,
        source_lat=db_threat.source_lat,
        source_lng=db_threat.source_lng,
        target_city=db_threat.target_city,
        attack_type=db_threat.attack_type,
        risk_score=db_threat.risk_score,
        risk_level=db_threat.risk_level,
        prediction=db_threat.prediction,
        threat_status=db_threat.threat_status,
        anomaly_score=db_threat.anomaly_score,
        is_anomalous=db_threat.is_anomalous,
        response_status=db_threat.response_status,
        timestamp=db_threat.timestamp.isoformat(),
    )

    # Broadcast only after the database transaction has succeeded.
    soc_ws_manager.broadcast_sync(
        {
            "type": "NEW_THREAT_EVENT",
            "event_id": threat_out.event_id,
            "event_type": threat_out.attack_type,
            "timestamp": threat_out.timestamp,
            "source_ip": threat_out.source_ip,
            "user_id": request.user_id or "Anonymous/System",
            "location": (
                f"{threat_out.source_city}, "
                f"{threat_out.source_country}"
            ),
            "risk_score": threat_out.risk_score,
            "risk_level": threat_out.risk_level,
            "prediction": threat_out.prediction,
            "anomaly_score": threat_out.anomaly_score,
            "response_status": threat_out.response_status,
            "policy_applied": audit_entry.policy_applied,
            "threat_record": threat_out.model_dump(),
        }
    )

    # Do not echo the caller's untrusted risk_score in the response.
    original_event = request.model_dump()
    original_details = dict(original_event.get("details") or {})
    original_details.pop("risk_score", None)
    original_event["details"] = original_details

    return CombinedThreatIngestResponse(
        message=(
            "Event ingested, evaluated by the server-side ML service, "
            "and processed by the response engine."
        ),
        original_event=original_event,
        ml_result=ml_result,
        threat_record=threat_out,
        audit_log=audit_entry.to_dict(),
    )
