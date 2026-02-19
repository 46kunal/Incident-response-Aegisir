import pandas as pd

def correlate_incidents(df):

    incidents = []
    df = df.sort_values("timestamp")

    incident_counter = 1

    for user in df["user"].unique():

        user_logs = df[df["user"] == user]

        for i in range(len(user_logs)):

            window_start = user_logs.iloc[i]["timestamp"]
            window_end = window_start + pd.Timedelta(minutes=30)

            window_logs = user_logs[
                (user_logs["timestamp"] >= window_start) &
                (user_logs["timestamp"] <= window_end)
            ]

            failed_count = int(window_logs["is_failed"].sum())
            unusual_ip = int(window_logs["is_unusual_ip"].sum())
            privilege = int(window_logs["is_privilege_escalation"].sum())
            sensitive = int(window_logs["is_sensitive_access"].sum())
            max_data_transfer = float(window_logs["data_volume_mb"].max())
            large_transfer = max_data_transfer > 500
            anomaly_count = int(len(window_logs[window_logs["anomaly_flag"] == -1]))

            if (
                failed_count >= 5 and
                unusual_ip >= 1 and
                privilege >= 1 and
                sensitive >= 1 and
                large_transfer and
                anomaly_count >= 2
            ):

                systems = [str(s) for s in window_logs["log_source"].unique()]

                # Ensure anomaly score is native float
                max_anomaly_score = float(window_logs["anomaly_score"].min())

                aggregated_risk = {
                    "failed_logins": failed_count,
                    "unusual_ip_events": unusual_ip,
                    "privilege_escalations": privilege,
                    "sensitive_access_events": sensitive,
                    "max_data_transfer_mb": max_data_transfer
                }

                # Convert timestamps safely to string
                timeline = window_logs.sort_values("timestamp").apply(
                    lambda row: {
                        "timestamp": row["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                        "log_source": str(row["log_source"])
                    },
                    axis=1
                ).tolist()

                incident = {
                    "incident_id": f"INC{incident_counter:03d}",
                    "user": str(user),
                    "incident_type": "Account Compromise + Data Exfiltration",
                    "start_time": window_start.strftime("%Y-%m-%d %H:%M:%S"),
                    "systems_affected": int(len(systems)),
                    "systems_involved": systems,
                    "events_count": int(len(window_logs)),
                    "anomalies_detected": anomaly_count,
                    "max_anomaly_score": max_anomaly_score,
                    "risk_summary": aggregated_risk,
                    "timeline": timeline
                }

                incidents.append(incident)
                incident_counter += 1
                break

    return incidents
