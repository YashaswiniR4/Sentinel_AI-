
"""
SentinelAI FastAPI Backend Core Integration & API Test Suite
Verifies:
- Root health check / and /docs
- Auth endpoints (/api/auth/login, /api/auth/register)
- Event Ingestion Pipeline (/api/events/ingest)
- ML Contract Bridge integration
- Cloud AutomatedResponseEngine & PolicyManager bridge integration
- Database persistence (SQLite)
"""

import os
import unittest
import uuid

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services.ml_service import MLService
from backend.app.db.base import Base
from backend.app.db.session import engine, SessionLocal
from backend.app.services.auth_service import seed_default_users_if_empty
from backend.app.services.telemetry_service import seed_initial_threats_if_empty


class TestSentinelAIBackend(unittest.TestCase):

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

    def _get_sensor_headers(self):
        """Return sensor authentication headers without exposing the key."""
        sensor_key = os.getenv("SENTINELAI_SENSOR_API_KEY")

        if not sensor_key:
            self.fail(
                "SENTINELAI_SENSOR_API_KEY is not available to Python. "
                "Configure it in the test environment before running tests."
            )

        return {"X-SentinelAI-Sensor-Key": sensor_key}

    def _get_user_headers(self):
        """Log in as the seeded regular user and return JWT headers."""
        response = self.client.post(
            "/api/auth/login",
            json={
                "username": "alex_sentinel",
                "password": "Password123!",
            },
        )

        self.assertEqual(
            response.status_code,
            200,
            f"Regular-user login failed: {response.text}",
        )

        token = response.json().get("access_token")
        self.assertTrue(
            token,
            "Login response did not contain an access token.",
        )

        return {"Authorization": f"Bearer {token}"}

    def _get_admin_headers(self):
        """Log in as the seeded SOC administrator and return JWT headers."""
        response = self.client.post(
            "/api/auth/login",
            json={
                "username": "admin",
                "password": "AdminSecure2026!",
            },
        )

        self.assertEqual(
            response.status_code,
            200,
            f"Admin login failed: {response.text}",
        )

        token = response.json().get("access_token")
        self.assertTrue(
            token,
            "Admin login response did not contain an access token.",
        )

        return {"Authorization": f"Bearer {token}"}

    def test_root_health_check(self):
        """GET / returns status online."""
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "online")
        self.assertEqual(data["health"], "OK")

    def test_docs_page_accessible(self):
        """GET /docs returns OpenAPI documentation HTML."""
        response = self.client.get("/docs")
        self.assertEqual(response.status_code, 200)

    def test_auth_login_default_user(self):
        """POST /api/auth/login authenticates the seeded default user."""
        response = self.client.post(
            "/api/auth/login",
            json={
                "username": "alex_sentinel",
                "password": "Password123!",
            },
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["role"], "user")

    def test_auth_login_admin_user(self):
        """POST /api/auth/login authenticates the seeded SOC admin."""
        response = self.client.post(
            "/api/auth/login",
            json={
                "username": "admin",
                "password": "AdminSecure2026!",
            },
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["role"], "admin")

    def test_auth_register_new_user(self):
        """Registration creates a user requiring OTP verification."""
        uid = uuid.uuid4().hex[:6]
        email = f"new.user.{uid}@example.com"

        response = self.client.post(
            "/api/auth/register",
            json={
                "email": email,
                "username": f"user_{uid}",
                "password": "MySecretPass123!",
                "name": "New Test User",
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(data["status"], "verification_required")
        self.assertEqual(data["email"], email)

    def test_ml_service_contract(self):
        """MLService adheres strictly to the expected five-field contract."""
        result = MLService.evaluate_event(
            "LOGIN_FAILED",
            details={"failed_count": 12},
        )

        self.assertIn("prediction", result)
        self.assertIn("threat", result)
        self.assertIn("anomaly_score", result)
        self.assertIn("risk_score", result)
        self.assertIn("risk_level", result)
        self.assertEqual(result["prediction"], -1)
        self.assertEqual(result["threat"], "Anomalous")
        self.assertEqual(result["risk_score"], 99.05)

    def test_event_ingestion_pipeline_low_risk(self):
        """Low-risk ingestion returns MONITOR and persists the audit record."""
        payload = {
            "event_type": "PASSWORD_CHANGE",
            "user_id": "alex_sentinel",
            "source_ip": "192.168.1.45",
            "device": "Windows PC",
            "browser": "Chrome 128",
            "location": "Mysuru, India",
            "details": {"risk_score": 10.0},
        }

        response = self.client.post(
            "/api/events/ingest",
            json=payload,
            headers=self._get_sensor_headers(),
        )

        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertGreaterEqual(data["ml_result"]["risk_score"], 0.0)
        self.assertLessEqual(data["ml_result"]["risk_score"], 100.0)
        self.assertEqual(data["audit_log"]["action"], "MONITOR")

    def test_event_ingestion_pipeline_high_risk_block_simulated(self):
        """High-risk ingestion triggers a simulated block and persists to DB."""
        payload = {
            "event_type": "LOGIN_FAILED",
            "user_id": "unknown_attacker",
            "source_ip": "198.51.100.99",
            "device": "Linux Workstation",
            "browser": "Firefox 125",
            "location": "Frankfurt, Germany",
            "source_country": "Germany",
            "source_city": "Frankfurt",
            "details": {
                "failed_count": 15,
                "risk_score": 95.0,
            },
        }

        response = self.client.post(
            "/api/events/ingest",
            json=payload,
            headers=self._get_sensor_headers(),
        )

        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(data["ml_result"]["prediction"], -1)
        self.assertEqual(
            data["threat_record"]["response_status"],
            "BLOCKED_SIMULATED",
        )
        self.assertTrue(data["audit_log"]["dry_run"])
        self.assertIn(
            "[BLOCK_SIMULATED]",
            data["audit_log"]["summary"],
        )

    def test_user_security_status_endpoint(self):
        """Security status requires an authenticated user."""
        response = self.client.get(
            "/api/user/security-status",
            headers=self._get_user_headers(),
        )

        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertIn("securityScore", data)
        self.assertIn("activitySummary", data)

    def test_soc_summary_metrics_endpoint(self):
        """GET /api/soc/metrics returns the metrics schema."""
        response = self.client.get(
            "/api/soc/metrics",
            headers=self._get_admin_headers(),
        )

        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertIn("activeCount", data)
        self.assertIn("blockedCount", data)

    def test_soc_attack_map_endpoint(self):
        """GET /api/soc/attack-map returns attack vectors."""
        response = self.client.get(
            "/api/soc/attack-map",
            headers=self._get_admin_headers(),
        )

        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertIn("honeypot", data)
        self.assertIn("vectors", data)

    def test_soar_policies_endpoint(self):
        """GET /api/mitigation/policies returns active SOAR policies."""
        response = self.client.get(
            "/api/mitigation/policies",
            headers=self._get_admin_headers(),
        )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(len(response.json()) >= 3)


if __name__ == "__main__":
    unittest.main()
