
"""
Cloud Automated Mitigation Service Bridge
Integrates backend telemetry with cloud.automated_response
and cloud.policy_manager.

Features:
- Threat telemetry processing
- SOAR policy listing
- Policy enable/disable
- Policy-change audit logging
- Audit-trail retrieval

Risk policies:
0-39.99   -> MONITOR
40-74.99  -> ALERT
75-100    -> BLOCK (dry-run simulation only)
"""

from typing import Any, Dict, List, Optional

from cloud.automated_response import (
    AutomatedResponseEngine,
    ThreatResult,
    AuditLogEntry,
)
from cloud.policy_manager import PolicyManager


class CloudMitigationService:
    """
    Connects the FastAPI backend to the cloud automated-response engine.

    Actual firewall blocking is not enabled. Critical-threat responses
    remain in dry-run mode.
    """

    def __init__(self) -> None:
        self.policy_manager = PolicyManager()

        self.engine = AutomatedResponseEngine(
            policy_manager=self.policy_manager,
            audit_log_path="cloud/audit_logs.jsonl",
            dry_run=True,
        )

    def process_threat_telemetry(
        self,
        event_id: str,
        source_ip: str,
        risk_score: float,
        threat_type: str = "ANOMALY_DETECTION",
        user_id: Optional[str] = None,
        location: str = "Unknown",
        is_anomalous: bool = False,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditLogEntry:
        """
        Construct a ThreatResult and process it through the
        automated-response engine.
        """

        threat = ThreatResult(
            event_id=event_id,
            source_ip=source_ip,
            risk_score=float(risk_score),
            threat_type=threat_type,
            user_id=user_id,
            location=location,
            is_anomalous=is_anomalous,
            details=details or {},
        )

        return self.engine.process_threat(threat)

    def get_soar_policies(self) -> List[Dict[str, Any]]:
        """
        Return the configured SOAR policies and their current states.
        """

        return [
            {
                "name": policy.name,
                "description": policy.description,
                "min_risk_score": policy.min_risk_score,
                "max_risk_score": policy.max_risk_score,
                "action": policy.action.value,
                "enabled": policy.enabled,
            }
            for policy in self.policy_manager.policies
        ]

    def toggle_soar_policy(
        self,
        policy_name: str,
        enabled: bool,
        admin_username: str = "unknown",
        source_ip: str = "unknown",
    ) -> bool:
        """
        Change a SOAR policy's enabled state and record the action
        in the audit trail.

        Returns:
            True if the policy was found and updated.
            False if the policy does not exist or the update fails.
        """

        # Locate the policy without changing its state.
        policy = next(
            (
                item
                for item in self.policy_manager.policies
                if item.name.lower() == policy_name.lower()
            ),
            None,
        )

        if policy is None:
            return False

        # Capture the state before the update.
        previous_enabled = policy.enabled

        # Apply the requested state.
        success = self.policy_manager.toggle_policy(
            policy.name,
            enabled,
        )

        if not success:
            return False

        # Record the successful policy action.
        # The updated automated_response.py must implement this method.
        self.engine.record_policy_change(
            policy_name=policy.name,
            previous_enabled=previous_enabled,
            enabled=enabled,
            admin_username=admin_username,
            source_ip=source_ip,
        )

        return True

    def get_audit_trail(self) -> List[Dict[str, Any]]:
        """
        Return audit-trail entries, including threat events and
        recorded policy changes.
        """

        return [
            entry.to_dict()
            for entry in self.engine.get_audit_trail()
        ]


# Shared service instance used by the API endpoints.
cloud_service = CloudMitigationService()
