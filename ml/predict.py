
import json
import math
import joblib
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MODEL_FILE = BASE_DIR / "model" / "isolation_forest.pkl"
STATS_FILE = BASE_DIR / "model" / "anomaly_score_stats.json"


def predict_activity(
    protocol,
    failed_attempts,
    session_duration,
    command_count,
    login_success,
    has_request,
    has_command,
    is_login_attempt,
    is_http_request
):
    if not MODEL_FILE.is_file():
        raise FileNotFoundError(f"Trained model not found: {MODEL_FILE}")

    if not STATS_FILE.is_file():
        raise FileNotFoundError(f"Anomaly score statistics not found: {STATS_FILE}")

    model = joblib.load(MODEL_FILE)

    with open(STATS_FILE, "r", encoding="utf-8") as file:
        stats = json.load(file)

    min_score = float(stats["min_score"])
    max_score = float(stats["max_score"])

    # Convert the incoming activity into the model's 12 training features.
    failed_attempts = max(0, int(failed_attempts or 0))
    duration = max(0.0, float(session_duration or 0))
    commands = max(0, int(command_count or 0))

    protocol_text = str(protocol).strip().lower()
    if protocol_text in ("http", "https", "api", "2"):
        protocol_numeric = 2.0
    else:
        protocol_numeric = 1.0

    login_success_flag = float(bool(login_success))
    is_login_event = float(bool(is_login_attempt))
    is_http_event = float(bool(is_http_request or has_request))

    auth_failure_ratio = (
        failed_attempts / (failed_attempts + 1.0)
        if failed_attempts > 0
        else 0.0
    )

    # These fields are not supplied by the existing function interface.
    # Use conservative defaults rather than inventing event details.
    transfer_burst_rate = 0.0
    endpoint_risk_depth = 0.1
    action_destructiveness = 0.0
    is_off_hours = 0.5

    data = pd.DataFrame([{
        "protocol_numeric": protocol_numeric,
        "failed_attempts": float(failed_attempts),
        "auth_failure_ratio": auth_failure_ratio,
        "session_duration": math.log1p(duration),
        "command_count": float(commands),
        "login_success_flag": login_success_flag,
        "is_login_event": is_login_event,
        "is_http_event": is_http_event,
        "transfer_burst_rate": transfer_burst_rate,
        "endpoint_risk_depth": endpoint_risk_depth,
        "action_destructiveness": action_destructiveness,
        "is_off_hours": is_off_hours,
    }])

    # Enforce exactly the same feature order used during training.
    feature_names = list(model.feature_names_in_)
    data = data[feature_names]

    prediction = int(model.predict(data)[0])
    anomaly_score = float(model.decision_function(data)[0])

    threat = "Anomalous" if prediction == -1 else "Normal"

    if max_score == min_score:
        risk_score = 0.0
    else:
        risk_score = (
            (max_score - anomaly_score) / (max_score - min_score)
        ) * 100.0

    risk_score = round(max(0.0, min(100.0, risk_score)), 2)

    if risk_score >= 75:
        risk_level = "Critical"
    elif risk_score >= 50:
        risk_level = "High"
    elif risk_score >= 25:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "prediction": prediction,
        "threat": threat,
        "anomaly_score": round(anomaly_score, 6),
        "risk_score": risk_score,
        "risk_level": risk_level
    }
