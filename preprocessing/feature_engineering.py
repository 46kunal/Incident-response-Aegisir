import pandas as pd

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