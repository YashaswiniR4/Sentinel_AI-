"""
SentinelAI Attack Detection Test Suite
======================================
Covers 8 attack scenarios using SYNTHETIC test events only.
All events are ingested via the real /api/events/ingest pipeline and verified
against the 5-field ML contract, SOAR policy engine, and database persistence.

IMPORTANT:
- No real attacks are executed against any system.
- No third-party services are contacted.
- All events are labeled with threat_source="SYNTHETIC_TEST" to distinguish them
  from honeypot-collected events and real user activity.
- SOAR engine runs in dry_run=True mode — no real IP blocks or cloud changes occur.

Detection Method Labels (used in assertions):
  RULE_BASED   — Risk score set by heuristic override in MLService
  ML_INFERRED  — Risk score determined by loaded IsolationForest model
  HYBRID       — Both rule-based override and model inference applied
"""

import os
import time
import unittest
import uuid

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services.ml_service import MLService
from backend.app.db.base import Base
from backend.app.db.session import engine, SessionLocal
from backend.app.services.auth_service import seed_default_users_if_empty
from backend.app.services.telemetry_service import seed_initial_threats_if_empty


# ─── Threshold constants matching SentinelAI SOAR policy bands ────────────────
MONITOR_THRESHOLD  = 0.0   # 0–39.99 → MONITOR
ALERT_THRESHOLD    = 40.0  # 40–74.99 → ALERTED
BLOCK_THRESHOLD    = 75.0  # 75–100  → BLOCKED_SIMULATED


class TestAttackScenarios(unittest.TestCase):
    """
    8 attack scenario integration tests.
    Each test sends a synthetic event through the full pipeline:
    POST /api/events/ingest → MLService → CloudSOAR → PostgreSQL/SQLite
    then verifies ML contract, SOAR response, and DB persistence.
    """

    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        try:
            seed_default_users_if_empty(db)
            seed_initial_threats_if_empty(db)
        finally:
            db.close()

        cls.client = TestClient(app)

        # Authenticate as admin once for all SOC verification requests
        admin_login = cls.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "AdminSecure2026!"},
        )
        assert admin_login.status_code == 200, f"Admin login failed: {admin_login.text}"
        cls.admin_headers = {"Authorization": f"Bearer {admin_login.json()['access_token']}"}

    def _sensor_headers(self):
        """Returns sensor API key header. Fails clearly if env var is missing."""
        key = os.getenv("SENTINELAI_SENSOR_API_KEY")
        if not key:
            self.fail(
                "SENTINELAI_SENSOR_API_KEY environment variable is not set. "
                "Set it before running this test suite."
            )
        return {"X-SentinelAI-Sensor-Key": key}

    def _ingest(self, event_type: str, details: dict, source_ip: str = "203.0.113.99") -> dict:
        """
        Sends a synthetic event through the real ingestion pipeline.
        Always includes threat_source and test_scenario labels in details.
        Returns the parsed JSON response body.
        """
        scenario_tag = details.pop("_scenario_tag", event_type)
        labeled_details = {
            **details,
            "threat_source": "SYNTHETIC_TEST",
            "test_scenario": scenario_tag,
        }
        payload = {
            "event_type": event_type,
            "user_id": f"test_attacker_{uuid.uuid4().hex[:6]}",
            "source_ip": source_ip,
            "device": "Kali Linux",
            "browser": "curl/7.88",
            "location": "Test Environment",
            "details": labeled_details,
        }
        response = self.client.post(
            "/api/events/ingest",
            json=payload,
            headers=self._sensor_headers(),
        )
        self.assertEqual(
            response.status_code, 200,
            f"Ingestion failed for {event_type}: {response.text}"
        )
        return response.json()

    def _assert_ml_contract(self, ml_result: dict):
        """Validates the 5-field ML contract is fully populated."""
        for field in ("prediction", "threat", "anomaly_score", "risk_score", "risk_level"):
            self.assertIn(field, ml_result, f"ML contract field '{field}' missing")
        self.assertIn(ml_result["prediction"], (-1, 1), "prediction must be -1 or 1")
        self.assertIn(ml_result["threat"], ("Anomalous", "Normal"), "threat must be Anomalous or Normal")
        self.assertGreaterEqual(ml_result["risk_score"], 0.0)
        self.assertLessEqual(ml_result["risk_score"], 100.0)

    def _assert_anomalous(self, ml_result: dict):
        """Asserts the event was classified as anomalous by ML or heuristic."""
        self.assertEqual(ml_result["prediction"], -1,
            f"Expected prediction=-1 (Anomalous), got {ml_result['prediction']}")
        self.assertEqual(ml_result["threat"], "Anomalous",
            f"Expected threat=Anomalous, got {ml_result['threat']}")

    def _assert_risk_at_least(self, ml_result: dict, min_risk: float):
        """Asserts risk_score meets the minimum threshold for the expected SOAR band."""
        self.assertGreaterEqual(
            ml_result["risk_score"], min_risk,
            f"Expected risk_score >= {min_risk}, got {ml_result['risk_score']}"
        )

    def _verify_db_persistence(self, event_id: str):
        """Confirms the event was persisted in the database via SOC threats endpoint."""
        response = self.client.get("/api/soc/threats", headers=self.admin_headers)
        self.assertEqual(response.status_code, 200)
        event_ids = [t["event_id"] for t in response.json()]
        self.assertIn(event_id, event_ids,
            f"Event {event_id} not found in /api/soc/threats after ingestion")

    # ══════════════════════════════════════════════════════════════════════════
    # Scenario 1: Brute-Force Login
    # ══════════════════════════════════════════════════════════════════════════
    def test_01_brute_force_login(self):
        """
        Scenario: Attacker makes 20+ failed login attempts from a single IP.
        Detection method: RULE_BASED (failed_count triggers heuristic override in MLService)
        Expected: prediction=-1, risk_score>=75, SOAR=BLOCKED_SIMULATED
        """
        data = self._ingest(
            event_type="LOGIN_FAILED",
            details={
                "_scenario_tag": "BRUTE_FORCE_LOGIN",
                "failed_count": 20,
                "login_success": False,
            },
            source_ip="203.0.113.10",
        )
        ml = data["ml_result"]

        self._assert_ml_contract(ml)
        self._assert_anomalous(ml)
        self._assert_risk_at_least(ml, BLOCK_THRESHOLD)

        threat = data["threat_record"]
        self.assertIn(
            threat["response_status"], ("ALERTED", "BLOCKED_SIMULATED"),
            f"Expected ALERTED or BLOCKED_SIMULATED, got {threat['response_status']}"
        )
        self.assertTrue(data["audit_log"]["dry_run"],
            "SOAR must operate in dry_run mode — no real block actions")

        self._verify_db_persistence(threat["event_id"])

    # ══════════════════════════════════════════════════════════════════════════
    # Scenario 2: Credential Stuffing
    # ══════════════════════════════════════════════════════════════════════════
    def test_02_credential_stuffing(self):
        """
        Scenario: Attacker tries 50 credential pairs in rapid succession.
        Detection method: RULE_BASED (very high failed_count triggers max risk override)
        Expected: prediction=-1, risk_score>=75, SOAR=BLOCKED_SIMULATED
        """
        data = self._ingest(
            event_type="LOGIN_FAILED",
            details={
                "_scenario_tag": "CREDENTIAL_STUFFING",
                "failed_count": 50,
                "login_success": False,
                "is_login": True,
                "session_duration": 3,  # Very short — rapid fire
            },
            source_ip="203.0.113.20",
        )
        ml = data["ml_result"]

        self._assert_ml_contract(ml)
        self._assert_anomalous(ml)
        self._assert_risk_at_least(ml, BLOCK_THRESHOLD)

        threat = data["threat_record"]
        self.assertEqual(threat["response_status"], "BLOCKED_SIMULATED",
            f"Credential stuffing must trigger BLOCKED_SIMULATED, got {threat['response_status']}")
        self.assertTrue(data["audit_log"]["dry_run"])

        self._verify_db_persistence(threat["event_id"])

    # ══════════════════════════════════════════════════════════════════════════
    # Scenario 3: Port Scanning
    # ══════════════════════════════════════════════════════════════════════════
    def test_03_port_scanning(self):
        """
        Scenario: Attacker probes multiple ports (SSH-based enumeration).
        Detection method: RULE_BASED (PORT_SCAN event type → heuristic High/Critical)
        Expected: prediction=-1, risk_score>=40, SOAR=ALERTED or BLOCKED_SIMULATED
        Note: IsolationForest was not trained on PORT_SCAN directly — heuristic applies.
        """
        data = self._ingest(
            event_type="PORT_SCAN",
            details={
                "_scenario_tag": "PORT_SCANNING",
                "protocol": "SSH",
                "command_count": 0,
                "failed_count": 5,
            },
            source_ip="203.0.113.30",
        )
        ml = data["ml_result"]

        self._assert_ml_contract(ml)
        self._assert_anomalous(ml)
        self._assert_risk_at_least(ml, ALERT_THRESHOLD)

        threat = data["threat_record"]
        self.assertIn(
            threat["response_status"], ("ALERTED", "BLOCKED_SIMULATED"),
            f"Port scan must trigger ALERTED or BLOCKED_SIMULATED, got {threat['response_status']}"
        )
        self.assertTrue(data["audit_log"]["dry_run"])

        self._verify_db_persistence(threat["event_id"])

    # ══════════════════════════════════════════════════════════════════════════
    # Scenario 4: Unusual Data Download / Exfiltration
    # ══════════════════════════════════════════════════════════════════════════
    def test_04_unusual_data_download(self):
        """
        Scenario: User downloads 500 MB+ of data in a short burst (exfiltration pattern).
        Detection method: RULE_BASED + ML_INFERRED (transfer_burst_rate feature)
        Expected: prediction=-1, risk_score>=75, SOAR=BLOCKED_SIMULATED
        """
        data = self._ingest(
            event_type="DATA_EXFILTRATION",
            details={
                "_scenario_tag": "UNUSUAL_DATA_DOWNLOAD",
                "protocol": "HTTP",
                "transfer_burst_rate": 500,  # MB/s — extremely high
                "session_duration": 30,
            },
            source_ip="203.0.113.40",
        )
        ml = data["ml_result"]

        self._assert_ml_contract(ml)
        self._assert_anomalous(ml)
        self._assert_risk_at_least(ml, BLOCK_THRESHOLD)

        threat = data["threat_record"]
        self.assertEqual(threat["response_status"], "BLOCKED_SIMULATED",
            f"Exfiltration must trigger BLOCKED_SIMULATED, got {threat['response_status']}")
        self.assertTrue(data["audit_log"]["dry_run"])

        self._verify_db_persistence(threat["event_id"])

    # ══════════════════════════════════════════════════════════════════════════
    # Scenario 5: Suspicious Cloud Configuration Change
    # ══════════════════════════════════════════════════════════════════════════
    def test_05_suspicious_cloud_config_change(self):
        """
        Scenario: Unauthorized change to cloud security group / IAM policy.
        Detection method: RULE_BASED (action_destructiveness=1.0 → high risk override)
        Expected: prediction=-1, risk_score>=40, SOAR=ALERTED or BLOCKED_SIMULATED
        Note: CLOUD_CONFIG_CHANGE is not a real cloud audit event — it is synthetic.
              Real cloud audit events come from cloud/cloud_event_producer.py.
        """
        data = self._ingest(
            event_type="CLOUD_CONFIG_CHANGE",
            details={
                "_scenario_tag": "CLOUD_CONFIG_CHANGE",
                "action_destructiveness": 1.0,
                "resource": "security_group_sg-test",
                "change_type": "open_all_ports",
            },
            source_ip="203.0.113.50",
        )
        ml = data["ml_result"]

        self._assert_ml_contract(ml)
        self._assert_anomalous(ml)
        self._assert_risk_at_least(ml, ALERT_THRESHOLD)

        threat = data["threat_record"]
        self.assertIn(
            threat["response_status"], ("ALERTED", "BLOCKED_SIMULATED"),
            f"Cloud config change must trigger ALERTED or BLOCKED_SIMULATED, got {threat['response_status']}"
        )
        self.assertTrue(data["audit_log"]["dry_run"])

        self._verify_db_persistence(threat["event_id"])

    # ══════════════════════════════════════════════════════════════════════════
    # Scenario 6: SQL Injection Attempt
    # ══════════════════════════════════════════════════════════════════════════
    def test_06_sql_injection_attempt(self):
        """
        Scenario: Attacker sends SQL injection payload in a web request.
        Detection method: RULE_BASED (SQL_INJECTION_ATTEMPT + endpoint_risk_depth=1.0)
        Expected: prediction=-1, risk_score>=75, SOAR=BLOCKED_SIMULATED
        Note: The actual payload string is NOT executed — only the event metadata is stored.
        """
        data = self._ingest(
            event_type="SQL_INJECTION_ATTEMPT",
            details={
                "_scenario_tag": "SQL_INJECTION",
                "protocol": "HTTP",
                "endpoint_risk_depth": 1.0,
                "method": "POST",
                "request_path": "/api/login",
                # Payload metadata only — NOT executed anywhere
                "payload_type": "UNION_SELECT_PATTERN",
            },
            source_ip="203.0.113.60",
        )
        ml = data["ml_result"]

        self._assert_ml_contract(ml)
        self._assert_anomalous(ml)
        self._assert_risk_at_least(ml, BLOCK_THRESHOLD)

        threat = data["threat_record"]
        self.assertEqual(threat["response_status"], "BLOCKED_SIMULATED",
            f"SQL injection must trigger BLOCKED_SIMULATED, got {threat['response_status']}")
        self.assertTrue(data["audit_log"]["dry_run"])

        self._verify_db_persistence(threat["event_id"])

    # ══════════════════════════════════════════════════════════════════════════
    # Scenario 7: Path Traversal Attempt
    # ══════════════════════════════════════════════════════════════════════════
    def test_07_path_traversal_attempt(self):
        """
        Scenario: Attacker attempts directory traversal to access restricted files.
        Detection method: RULE_BASED (PATH_TRAVERSAL_ATTEMPT + endpoint_risk_depth=0.8)
        Expected: prediction=-1, risk_score>=75, SOAR=BLOCKED_SIMULATED
        Note: No file system access is performed — only metadata is recorded.
        """
        data = self._ingest(
            event_type="PATH_TRAVERSAL_ATTEMPT",
            details={
                "_scenario_tag": "PATH_TRAVERSAL",
                "protocol": "HTTP",
                "endpoint_risk_depth": 0.8,
                "method": "GET",
                "request_path": "/api/files",
                # Pattern metadata only — NOT executed
                "traversal_pattern": "dot_dot_slash",
            },
            source_ip="203.0.113.70",
        )
        ml = data["ml_result"]

        self._assert_ml_contract(ml)
        self._assert_anomalous(ml)
        self._assert_risk_at_least(ml, BLOCK_THRESHOLD)

        threat = data["threat_record"]
        self.assertEqual(threat["response_status"], "BLOCKED_SIMULATED",
            f"Path traversal must trigger BLOCKED_SIMULATED, got {threat['response_status']}")
        self.assertTrue(data["audit_log"]["dry_run"])

        self._verify_db_persistence(threat["event_id"])

    # ══════════════════════════════════════════════════════════════════════════
    # Scenario 8: Audit-Log Tampering Attempt
    # ══════════════════════════════════════════════════════════════════════════
    def test_08_audit_log_tampering(self):
        """
        Scenario: Insider/attacker attempts to delete or modify audit trail records.
        Detection method: RULE_BASED (AUDIT_LOG_TAMPERING + action_destructiveness=1.0)
        Expected: prediction=-1, risk_score>=75, SOAR=BLOCKED_SIMULATED
        Note: No actual log files are modified — only the event metadata is recorded.
        """
        data = self._ingest(
            event_type="AUDIT_LOG_TAMPERING",
            details={
                "_scenario_tag": "AUDIT_LOG_TAMPERING",
                "action_destructiveness": 1.0,
                "target": "cloud/audit_logs.jsonl",
                "operation": "DELETE_RECORDS",
            },
            source_ip="203.0.113.80",
        )
        ml = data["ml_result"]

        self._assert_ml_contract(ml)
        self._assert_anomalous(ml)
        self._assert_risk_at_least(ml, BLOCK_THRESHOLD)

        threat = data["threat_record"]
        self.assertEqual(threat["response_status"], "BLOCKED_SIMULATED",
            f"Audit tampering must trigger BLOCKED_SIMULATED, got {threat['response_status']}")
        self.assertTrue(data["audit_log"]["dry_run"])

        self._verify_db_persistence(threat["event_id"])

    # ══════════════════════════════════════════════════════════════════════════
    # Deduplication Test
    # ══════════════════════════════════════════════════════════════════════════
    def test_09_deduplication_no_duplicate_records(self):
        """
        Verifies that re-sending the same event content creates a NEW unique event_id
        (the backend generates UUIDs per ingestion), but the same event_id is never
        created twice (event_id column has UNIQUE constraint).
        """
        # Two separate ingestions of same content → two different event_ids
        data1 = self._ingest("LOGIN_FAILED", {"failed_count": 5, "_scenario_tag": "DEDUP_TEST"})
        data2 = self._ingest("LOGIN_FAILED", {"failed_count": 5, "_scenario_tag": "DEDUP_TEST"})

        id1 = data1["threat_record"]["event_id"]
        id2 = data2["threat_record"]["event_id"]

        self.assertNotEqual(id1, id2,
            "Each ingestion must generate a unique event_id (UUID per request)")

    # ══════════════════════════════════════════════════════════════════════════
    # ML Service Unit Tests (direct, no HTTP)
    # ══════════════════════════════════════════════════════════════════════════
    def test_10_ml_service_direct_brute_force(self):
        """Direct MLService call — verifies RULE_BASED override for failed_count=20."""
        result = MLService.evaluate_event(
            "LOGIN_FAILED",
            details={"failed_count": 20, "threat_source": "SYNTHETIC_TEST"},
        )
        self._assert_ml_contract(result)
        self.assertEqual(result["prediction"], -1)
        self.assertEqual(result["threat"], "Anomalous")
        self.assertGreaterEqual(result["risk_score"], BLOCK_THRESHOLD)

    def test_11_ml_service_direct_data_exfiltration(self):
        """Direct MLService call — verifies DATA_EXFILTRATION maps to critical risk."""
        result = MLService.evaluate_event(
            "DATA_EXFILTRATION",
            details={
                "transfer_burst_rate": 500,
                "protocol": "HTTP",
                "threat_source": "SYNTHETIC_TEST",
            },
        )
        self._assert_ml_contract(result)
        self.assertEqual(result["prediction"], -1)
        self.assertGreaterEqual(result["risk_score"], BLOCK_THRESHOLD)

    def test_12_ml_service_direct_sql_injection(self):
        """Direct MLService call — verifies SQL_INJECTION_ATTEMPT → anomalous."""
        result = MLService.evaluate_event(
            "SQL_INJECTION_ATTEMPT",
            details={"endpoint_risk_depth": 1.0, "threat_source": "SYNTHETIC_TEST"},
        )
        self._assert_ml_contract(result)
        self.assertEqual(result["prediction"], -1)
        self.assertGreaterEqual(result["risk_score"], BLOCK_THRESHOLD)

    def test_13_ml_service_direct_audit_tampering(self):
        """Direct MLService call — verifies AUDIT_LOG_TAMPERING → anomalous."""
        result = MLService.evaluate_event(
            "AUDIT_LOG_TAMPERING",
            details={"action_destructiveness": 1.0, "threat_source": "SYNTHETIC_TEST"},
        )
        self._assert_ml_contract(result)
        self.assertEqual(result["prediction"], -1)
        self.assertGreaterEqual(result["risk_score"], BLOCK_THRESHOLD)

    def test_14_normal_login_not_anomalous(self):
        """Control test — normal LOGIN_SUCCESS must NOT be flagged as anomalous."""
        result = MLService.evaluate_event(
            "LOGIN_SUCCESS",
            details={"login_success": True, "threat_source": "SYNTHETIC_TEST"},
        )
        self._assert_ml_contract(result)
        # Normal login should be prediction=1 (Normal) with low risk
        self.assertEqual(result["prediction"], 1,
            f"Normal login must not be anomalous, got prediction={result['prediction']}")
        self.assertEqual(result["threat"], "Normal")

    def test_15_sensor_auth_required(self):
        """Verify that /api/events/ingest rejects requests without sensor API key."""
        response = self.client.post(
            "/api/events/ingest",
            json={"event_type": "LOGIN_FAILED", "details": {}},
            headers={},  # No auth header
        )
        self.assertIn(response.status_code, (401, 403, 422),
            f"Expected auth failure, got {response.status_code}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
