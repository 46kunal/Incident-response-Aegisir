🛡️ AegisIR – Autonomous Cyber Incident Response System

AI-powered incident detection and response system designed for banking environments.

🔍 What It Does

Ingests authentication, endpoint, and network logs

Detects anomalies using Isolation Forest

Correlates multi-stage attack patterns

Assigns severity score (Low → Critical)

Maps incidents to MITRE ATT&CK techniques

Generates structured response playbook using offline LLM

🧠 Tech Stack

Python

Scikit-learn

Streamlit

Ollama (Llama3 / Phi3)

Pandas

▶️ How to Run
1. Install dependencies
pip install streamlit pandas scikit-learn ollama

2. Install Ollama model
ollama pull llama3

3. Run application
streamlit run app.py

🚀 Workflow

Upload JSON logs

Click Start Security Scan

System performs:

Anomaly detection

Event correlation

Severity scoring

MITRE mapping

AI-generated response playbook
