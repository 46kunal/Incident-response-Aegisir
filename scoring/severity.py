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
