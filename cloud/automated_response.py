
"""
SentinelAI Cloud & Automated Response Engine
Threat response and SOAR audit logging.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
from typing import Dict, List, Optional
from uuid import uuid4

from cloud.policy_manager import PolicyManager, ResponseAction, ResponsePolicy

logger = logging.getLogger("SentinelAI.AutomatedResponse")


@dataclass
class ThreatResult:
    event_id: str
    source_ip: str
    risk_score: float
    threat_type: str = "ANOMALY_DETECTION"
    user_id: Optional[str] = None
    location: str = "Unknown"
    is_anomalous: bool = False
    details: Dict = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.risk_score, (int, float)):
            raise ValueError("risk_score must be an integer or float")
        if not 0.0 <= self.risk_score <= 100.0:
            raise ValueError("risk_score must be between 0 and 100")


@dataclass
class AuditLogEntry:
    log_id: str
    timestamp: str
    event_id: str
    source_ip: str
    risk_score: float
    action: str
    policy_applied: str
    dry_run: bool
    summary: str
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "log_id": self.log_id,
            "timestamp": self.timestamp,
            "event_id": self.event_id,
            "source_ip": self.source_ip,
            "risk_score": self.risk_score,
            "action": self.action,
            "policy_applied": self.policy_applied,
            "dry_run": self.dry_run,
            "summary": self.summary,
            "metadata": self.metadata,
        }


class AutomatedResponseEngine:
    """Evaluate threat policies and record threat and policy-change audit events."""

    def __init__(
        self,
        policy_manager: Optional[PolicyManager] = None,
        audit_log_path: str = "cloud/audit_logs.jsonl",
        dry_run: bool = True,
    ):
        self.policy_manager = policy_manager or PolicyManager()
        self.audit_log_path = audit_log_path
        self.dry_run = dry_run
        self.audit_trail: List[AuditLogEntry] = []

    def _next_log_id(self) -> str:
        """Generate a practically unique ID without relying on an instance counter."""
        return f"SOAR-LOG-{uuid4().hex[:12].upper()}"

    def _record_entry(self, entry: AuditLogEntry) -> AuditLogEntry:
        self.audit_trail.append(entry)
        self._persist_log_entry(entry)
        logger.info("[%s] %s", entry.action, entry.summary)
        return entry

    @classmethod
    def process_event(
        cls,
        event_id: str,
        source_ip: str,
        risk_score: float,
        event_type: str = "ANOMALY_DETECTION",
        user_id: Optional[str] = None,
        location: str = "Unknown",
        is_anomalous: bool = False,
        details: Optional[Dict] = None,
    ) -> Dict:
        engine = cls()

        threat = ThreatResult(
            event_id=event_id,
            source_ip=source_ip,
            risk_score=float(risk_score),
            threat_type=event_type,
            user_id=user_id,
            location=location,
            is_anomalous=is_anomalous,
            details=details or {},
        )

        entry = engine.process_threat(threat)

        response_status = (
            "MONITOR"
            if risk_score < 40
            else "ALERT"
            if risk_score < 75
            else "BLOCK_SIMULATED"
        )

        return {
            "action": entry.action,
            "response_status": response_status,
            "policy_applied": entry.policy_applied,
            "dry_run": entry.dry_run,
            "summary": entry.summary,
            "log_id": entry.log_id,
        }

    def evaluate_threat(self, threat: ThreatResult) -> ResponsePolicy:
        policy = self.policy_manager.get_policy_for_score(threat.risk_score)

        if policy is None:
            raise ValueError(
                "No active response policy found or policy is disabled "
                f"for risk score {threat.risk_score}."
            )

        return policy

    def process_threat(self, threat: ThreatResult) -> AuditLogEntry:
        policy = self.evaluate_threat(threat)
        action = policy.action

        if action == ResponseAction.MONITOR:
            summary = (
                f"Event [{threat.event_id}] logged under monitoring "
                f"(Risk Score: {threat.risk_score}/100)."
            )
            is_dry = False

        elif action == ResponseAction.ALERT:
            summary = (
                f"Security Alert triggered for IP {threat.source_ip} "
                f"(Risk Score: {threat.risk_score}/100)."
            )
            is_dry = False

        else:
            summary = (
                f"[BLOCK_SIMULATED] Simulated firewall block for IP "
                f"{threat.source_ip} (Risk Score: {threat.risk_score}/100). "
                "No real IP ban enforced."
            )
            is_dry = True

        entry = AuditLogEntry(
            log_id=self._next_log_id(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_id=threat.event_id,
            source_ip=threat.source_ip,
            risk_score=float(threat.risk_score),
            action=action.value,
            policy_applied=policy.name,
            dry_run=is_dry,
            summary=summary,
            metadata={
                "threat_type": threat.threat_type,
                "location": threat.location,
                "user_id": threat.user_id,
                "is_anomalous": threat.is_anomalous,
                "details": threat.details,
            },
        )

        return self._record_entry(entry)

    def record_policy_change(
        self,
        policy_name: str,
        previous_enabled: bool,
        enabled: bool,
        admin_username: str,
        source_ip: str = "unknown",
    ) -> AuditLogEntry:
        """Audit a successful policy toggle with the admin and old/new states."""

        previous_word = "enabled" if previous_enabled else "disabled"
        state_word = "enabled" if enabled else "disabled"

        entry = AuditLogEntry(
            log_id=self._next_log_id(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_id=f"POLICY-{uuid4().hex[:12].upper()}",
            source_ip=source_ip or "unknown",
            risk_score=0.0,
            action="POLICY_UPDATE",
            policy_applied=policy_name,
            dry_run=False,
            summary=(
                f"Admin '{admin_username}' set policy '{policy_name}' "
                f"to {state_word} (previously {previous_word})."
            ),
            metadata={
                "event_type": "POLICY_CHANGE",
                "admin_username": admin_username,
                "policy_name": policy_name,
                "previous_enabled": previous_enabled,
                "enabled": enabled,
            },
        )

        return self._record_entry(entry)

    def _persist_log_entry(self, entry: AuditLogEntry) -> None:
        try:
            dirname = os.path.dirname(self.audit_log_path)

            if dirname:
                os.makedirs(dirname, exist_ok=True)

            with open(self.audit_log_path, "a", encoding="utf-8") as file:
                file.write(json.dumps(entry.to_dict()) + "\n")

        except Exception as err:
            logger.error(
                "Failed to persist audit log entry to %s: %s",
                self.audit_log_path,
                err,
            )

    def get_audit_trail(self) -> List[AuditLogEntry]:
        return list(self.audit_trail)

    def clear_audit_trail(self) -> None:
        """Clear only this instance's in-memory audit trail."""
        self.audit_trail.clear()
