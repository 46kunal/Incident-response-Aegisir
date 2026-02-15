import json
import pandas as pd
from sklearn.ensemble import IsolationForest
import ollama


# ----------------------------
# 1️⃣ Load JSON Logs
# ----------------------------

def load_logs():
    with open("auth_logs.json", "r") as f:
        auth_logs = json.load(f)

    with open("endpoint_logs.json", "r") as f:
        endpoint_logs = json.load(f)

    with open("network_logs.json", "r") as f:
        network_logs = json.load(f)

    return auth_logs, endpoint_logs, network_logs


# ----------------------------
# 2️⃣ Feature Engineering
# ----------------------------

def preprocess_logs(auth_logs, endpoint_logs, network_logs):

    all_records = []

    for log in auth_logs:
        all_records.append({
            "timestamp": log["timestamp"],
            "user": log["user"],
            "log_source": "auth",
            "is_failed": 1 if log.get("status") == "failed" else 0,
            "is_unusual_ip": 0 if log.get("ip", "").startswith("192.168") else 1,
            "is_privilege_escalation": 0,
            "is_sensitive_access": 0,
            "data_volume_mb": 0
        })

    for log in endpoint_logs:
        all_records.append({
            "timestamp": log["timestamp"],
            "user": log["user"],
            "log_source": "endpoint",
            "is_failed": 0,
            "is_unusual_ip": 0,
            "is_privilege_escalation": 1 if log.get("event_type") == "privilege_escalation" else 0,
            "is_sensitive_access": 1 if log.get("sensitive_access") else 0,
            "data_volume_mb": 0
        })

    for log in network_logs:
        all_records.append({
            "timestamp": log["timestamp"],
            "user": log["user"],
            "log_source": "network",
            "is_failed": 0,
            "is_unusual_ip": 0,
            "is_privilege_escalation": 0,
            "is_sensitive_access": 0,
            "data_volume_mb": log.get("data_volume_mb", 0)
        })

    df = pd.DataFrame(all_records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["hour"] = df["timestamp"].dt.hour

    return df


# ----------------------------
# 3️⃣ Train Isolation Forest
# ----------------------------

def train_anomaly_model(df):

    feature_columns = [
        "is_failed",
        "is_unusual_ip",
        "is_privilege_escalation",
        "is_sensitive_access",
        "data_volume_mb",
        "hour"
    ]

    X = df[feature_columns]

    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)

    df["anomaly_score"] = model.decision_function(X)
    df["anomaly_flag"] = model.predict(X)

    return df, model


# ----------------------------
# 4️⃣ Correlation Engine
# ----------------------------

def correlate_incidents(df):

    incidents = []
    df = df.sort_values("timestamp")

    for user in df["user"].unique():

        user_logs = df[df["user"] == user]

        for i in range(len(user_logs)):

            window_start = user_logs.iloc[i]["timestamp"]
            window_end = window_start + pd.Timedelta(minutes=30)

            window_logs = user_logs[
                (user_logs["timestamp"] >= window_start) &
                (user_logs["timestamp"] <= window_end)
            ]

            failed_count = window_logs["is_failed"].sum()
            unusual_ip = window_logs["is_unusual_ip"].sum()
            privilege = window_logs["is_privilege_escalation"].sum()
            sensitive = window_logs["is_sensitive_access"].sum()
            large_transfer = window_logs["data_volume_mb"].max() > 500
            anomaly_count = len(window_logs[window_logs["anomaly_flag"] == -1])

            if (
                failed_count >= 5 and
                unusual_ip >= 1 and
                privilege >= 1 and
                sensitive >= 1 and
                large_transfer and
                anomaly_count >= 2
            ):
                systems = list(window_logs["log_source"].unique())

                incident = {
                    "incident_id": "INC001",
                    "user": user,
                    "incident_type": "Account Compromise + Data Exfiltration",
                    "start_time": str(window_start),
                    "systems_affected": len(systems),
                    "systems_involved": systems,
                    "events_count": len(window_logs),
                    "anomalies_detected": anomaly_count
                }

                incidents.append(incident)
                break

    return incidents


# ----------------------------
# 5️⃣ Severity Scoring
# ----------------------------

def calculate_severity(incident):

    anomaly_intensity = incident["anomalies_detected"] / incident["events_count"]
    systems_impact = incident["systems_affected"] / 3
    event_density = min(incident["events_count"] / 10, 1)
    data_exfiltration_factor = 1

    severity_score = (
        0.4 * anomaly_intensity +
        0.3 * systems_impact +
        0.2 * event_density +
        0.1 * data_exfiltration_factor
    )

    if severity_score >= 0.8:
        level = "Critical"
    elif severity_score >= 0.6:
        level = "High"
    elif severity_score >= 0.4:
        level = "Medium"
    else:
        level = "Low"

    return {
        "severity_score": round(severity_score, 3),
        "severity_level": level
    }


# ----------------------------
# 6️⃣ MITRE Mapping
# ----------------------------

def map_to_mitre(incident):

    mapping = []

    if "Account Compromise" in incident["incident_type"]:
        mapping += ["Initial Access", "Credential Access", "Privilege Escalation"]

    if "Data Exfiltration" in incident["incident_type"]:
        mapping.append("Exfiltration")

    return mapping


# ----------------------------
# 7️⃣ Playbook Generation (LLM)
# ----------------------------

def generate_playbook(incident):

    prompt = f"""
You are an enterprise-grade SOC automation engine.

Incident Type: {incident['incident_type']}
Severity Level: {incident['severity_level']}
Systems Involved: {", ".join(incident['systems_involved'])}
MITRE ATT&CK Mapping: {", ".join(incident['mitre_mapping'])}

Generate a structured incident response playbook with:

1. Immediate Containment Steps
2. Investigation Actions
3. Eradication Measures
4. Recovery Steps
5. Post-Incident Recommendations

Keep it professional and concise.
"""

    try:
        response = ollama.chat(
            model="llama3",
            messages=[{"role": "user", "content": prompt}]
        )
        return response["message"]["content"]

    except Exception:
        return "Playbook generation failed. Ensure Ollama is installed and running."


# ----------------------------
# 8️⃣ Main Pipeline
# ----------------------------

def run_detection_pipeline(auth_logs=None, endpoint_logs=None, network_logs=None):

    if auth_logs is None or endpoint_logs is None or network_logs is None:
        auth_logs, endpoint_logs, network_logs = load_logs()

    df = preprocess_logs(auth_logs, endpoint_logs, network_logs)
    df, model = train_anomaly_model(df)

    incidents = correlate_incidents(df)

    for incident in incidents:
        incident.update(calculate_severity(incident))
        incident["mitre_mapping"] = map_to_mitre(incident)
        incident["playbook"] = generate_playbook(incident)

    total_anomalies = len(df[df["anomaly_flag"] == -1])

    return {
        "total_logs": len(df),
        "total_anomalies": total_anomalies,
        "incidents": incidents
    }



# ----------------------------
# 9️⃣ Standalone Execution
# ----------------------------

if __name__ == "__main__":
    results = run_detection_pipeline()
    print(results)
