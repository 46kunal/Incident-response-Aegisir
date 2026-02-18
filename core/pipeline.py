from preprocessing.feature_engineering import preprocess_logs
from detection.anomaly_model import train_anomaly_model
from correlation.engine import correlate_incidents
from scoring.severity import calculate_severity
from mapping.mitre import map_to_mitre
from response.llm_playbook import generate_playbook
from audit.logger import write_audit_log


def run_detection_pipeline(auth_logs, endpoint_logs, network_logs):

    df = preprocess_logs(auth_logs, endpoint_logs, network_logs)

    df, model = train_anomaly_model(df)

    incidents = correlate_incidents(df)

    for incident in incidents:
        incident.update(calculate_severity(incident))
        incident["mitre_mapping"] = map_to_mitre(incident)
        incident["playbook"] = generate_playbook(incident)

    total_anomalies = len(df[df["anomaly_flag"] == -1])

    results = {
        "total_logs": len(df),
        "total_anomalies": total_anomalies,
        "incidents": incidents
    }

    write_audit_log(results)

    return results
