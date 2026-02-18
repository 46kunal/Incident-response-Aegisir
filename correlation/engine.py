import pandas as pd

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