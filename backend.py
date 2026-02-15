from severity import calculate_severity
from llm_engine import generate_playbook

def process_incident(data):

    anomaly_score = data["anomaly_score"]
    systems = data["systems_affected"]
    asset_weight = data["asset_criticality"]
    frequency = data["event_frequency"]

    final_score, severity_level = calculate_severity(
        anomaly_score,
        systems,
        asset_weight,
        frequency
    )

    playbook, prompt = generate_playbook(
        data["incident_type"],
        data["signals"],
        severity_level
    )
def map_to_mitre(incident_type):

    if incident_type == "Account Compromise":
        return "Initial Access → Credential Access → Privilege Escalation"

    elif incident_type == "Data Exfiltration":
        return "Exfiltration → Command and Control"

    else:
        return "Suspicious Activity – Under Investigation"


    return {
        "final_score": final_score,
        "severity": severity_level,
        "playbook": playbook,
        "audit_prompt": prompt,
        "mitre_mapping": mitre_mapping
    }
