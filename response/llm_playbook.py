import ollama

def generate_playbook(incident):

    system_prompt = """
You are a cybersecurity incident response assistant.

Rules:
- Do NOT generate shell commands.
- Do NOT include system execution commands.
- Do NOT include external URLs.
- Provide advisory steps only.
- Keep response structured and professional.
- Focus on containment, investigation, eradication, recovery, and prevention.
"""

    user_prompt = f"""
Incident Type: {incident['incident_type']}
Severity Level: {incident['severity_level']}
Systems Involved: {", ".join(incident['systems_involved'])}
MITRE ATT&CK Mapping: {", ".join(incident['mitre_mapping'])}

Generate a structured response playbook with:

1. Immediate Containment Steps
2. Investigation Actions
3. Eradication Measures
4. Recovery Steps
5. Post-Incident Recommendations
"""

    try:
        response = ollama.chat(
            model="llama3",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            options={
                "temperature": 0.2,
                "top_p": 0.8
            }
        )

        content = response["message"]["content"]

        # Basic safety filtering
        forbidden_keywords = ["sudo", "rm -rf", "shutdown", "format", "wget", "curl"]

        for keyword in forbidden_keywords:
            if keyword in content.lower():
                return "Generated response contained unsafe instructions and was blocked."

        return content

    except Exception:
        return "Playbook generation failed. Ensure Ollama is installed and running."