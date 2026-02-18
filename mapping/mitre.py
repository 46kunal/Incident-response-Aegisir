def map_to_mitre(incident):

    mapping = []

    if "Account Compromise" in incident["incident_type"]:
        mapping += ["Initial Access", "Credential Access", "Privilege Escalation"]

    if "Data Exfiltration" in incident["incident_type"]:
        mapping.append("Exfiltration")

    return mapping