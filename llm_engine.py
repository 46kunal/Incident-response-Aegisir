import ollama

def generate_playbook(incident_type, signals, severity):

    prompt = f"""
    You are a SOC automation engine.
    Incident Type: {incident_type}
    Detected Signals: {signals}
    Severity Level: {severity}

    Generate a structured step-by-step containment and remediation playbook.
    Format:
    1. Immediate Containment
    2. Investigation Steps
    3. Recovery Actions
    4. Post-Incident Monitoring
    """

    response = ollama.chat(
        model='llama3',
        messages=[{'role': 'user', 'content': prompt}]
    )

    return response['message']['content'], prompt
