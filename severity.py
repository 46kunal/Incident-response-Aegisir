def calculate_severity(anomaly_score, systems_affected, asset_weight, frequency):

    score = (
        0.4 * anomaly_score +
        0.3 * systems_affected +
        0.2 * asset_weight +
        0.1 * frequency
    )

    if score >= 0.8:
        level = "Critical"
    elif score >= 0.6:
        level = "High"
    elif score >= 0.3:
        level = "Medium"
    else:
        level = "Low"

    return round(score,2), level
