import streamlit as st
import json
import sys
import os

# Allow importing core modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.pipeline import run_detection_pipeline
from security.validator import validate_file_size, validate_logs

# ----------------------------
# Page Config
# ----------------------------

st.set_page_config(
    page_title="AegisIR Secure Access",
    layout="wide"
)

# ----------------------------
# Custom Professional CSS
# ----------------------------

st.markdown("""
<style>
body {
    background-color: #0f172a;
}

.main-title {
    text-align: center;
    font-size: 32px;
    font-weight: bold;
    color: white;
    margin-bottom: 20px;
}

.login-card {
    background-color: #1e293b;
    padding: 30px;
    border-radius: 12px;
    box-shadow: 0px 0px 15px rgba(0,0,0,0.5);
}

.role-badge {
    background-color: #2563eb;
    padding: 5px 10px;
    border-radius: 8px;
    color: white;
    font-size: 14px;
}
</style>
""", unsafe_allow_html=True)

# ----------------------------
# Static Users (Prototype RBAC)
# ----------------------------

USERS = {
    "admin": {"password": "admin123", "role": "Admin"},
    "analyst": {"password": "analyst123", "role": "SOC Analyst"},
    "auditor": {"password": "auditor123", "role": "Auditor"}
}

# ----------------------------
# Session Init
# ----------------------------

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.role = None
    st.session_state.results = None

# ----------------------------
# Login Screen
# ----------------------------

if not st.session_state.authenticated:

    st.markdown("<div class='main-title'>🛡 AegisIR Secure Access Portal</div>", unsafe_allow_html=True)

    with st.container():
        st.markdown("<div class='login-card'>", unsafe_allow_html=True)

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login Securely"):
            if username in USERS and USERS[username]["password"] == password:
                st.session_state.authenticated = True
                st.session_state.role = USERS[username]["role"]
                st.success(f"Access Granted: {st.session_state.role}")
                st.rerun()
            else:
                st.error("Invalid credentials")

        st.markdown("</div>", unsafe_allow_html=True)

    st.stop()

# ----------------------------
# Logged In View
# ----------------------------

st.markdown(
    f"<div class='main-title'>AegisIR SOC Dashboard</div>"
    f"<div style='text-align:center'><span class='role-badge'>{st.session_state.role}</span></div>",
    unsafe_allow_html=True
)

st.sidebar.header("📂 Upload Log Files")

auth_file = st.sidebar.file_uploader("Auth Logs (JSON)", type=["json"])
endpoint_file = st.sidebar.file_uploader("Endpoint Logs (JSON)", type=["json"])
network_file = st.sidebar.file_uploader("Network Logs (JSON)", type=["json"])

if auth_file and endpoint_file and network_file:

    try:
        validate_file_size(auth_file)
        validate_file_size(endpoint_file)
        validate_file_size(network_file)

        auth_logs = json.loads(auth_file.getvalue().decode("utf-8"))
        endpoint_logs = json.loads(endpoint_file.getvalue().decode("utf-8"))
        network_logs = json.loads(network_file.getvalue().decode("utf-8"))

        if isinstance(auth_logs, dict) and "logs" in auth_logs:
            auth_logs = auth_logs["logs"]

        validate_logs(auth_logs)
        validate_logs(endpoint_logs)
        validate_logs(network_logs)

        if st.sidebar.button("Start Security Scan"):
            with st.spinner("Running AI-powered detection..."):
                st.session_state.results = run_detection_pipeline(
                    auth_logs,
                    endpoint_logs,
                    network_logs
                )

    except Exception as e:
        st.error(f"Error: {str(e)}")

if st.session_state.results:

    results = st.session_state.results

    st.markdown("---")

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Logs", results["total_logs"])
    col2.metric("Anomalies", results["total_anomalies"])
    col3.metric("Incidents", len(results["incidents"]))

    st.markdown("---")

    # ----------------------------
    # INCIDENT DASHBOARD SECTION
    # ----------------------------

import json

if results["incidents"]:

    st.markdown("---")
    st.subheader("🚨 Active Incidents")

    # Incident Selector (Scalable View)
    incident_ids = [inc["incident_id"] for inc in results["incidents"]]
    selected_id = st.selectbox("Select Incident", incident_ids)

    incident = next(inc for inc in results["incidents"] if inc["incident_id"] == selected_id)

    st.markdown("---")

    # Severity Mapping
    severity_map = {
        "Low": 25,
        "Medium": 50,
        "High": 75,
        "Critical": 100
    }

    severity_percent = severity_map.get(incident["severity_level"], 0)
    confidence_percent = round(abs(incident["max_anomaly_score"]) * 100, 2)

    # Top Overview Section
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 📌 Incident Overview")
        st.write("**Incident ID:**", incident["incident_id"])
        st.write("**User:**", incident["user"])
        st.write("**Type:**", incident["incident_type"])
        st.write("**Start Time:**", incident["start_time"])
        st.write("**Systems Affected:**", incident["systems_affected"])
        st.write("**Events in Window:**", incident["events_count"])
        st.write("**Anomalies Detected:**", incident["anomalies_detected"])

    with col2:
        st.markdown("### 🔎 Detection Intelligence")

        # Severity Badge
        if incident["severity_level"] == "Critical":
            st.markdown(
                f"<h3 style='color:#ff4b4b;'>Severity: {incident['severity_level']} ({severity_percent}%)</h3>",
                unsafe_allow_html=True
            )
        elif incident["severity_level"] == "High":
            st.markdown(
                f"<h3 style='color:#ffa500;'>Severity: {incident['severity_level']} ({severity_percent}%)</h3>",
                unsafe_allow_html=True
            )
        elif incident["severity_level"] == "Medium":
            st.markdown(
                f"<h3 style='color:#ffd700;'>Severity: {incident['severity_level']} ({severity_percent}%)</h3>",
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f"<h3 style='color:#1e90ff;'>Severity: {incident['severity_level']} ({severity_percent}%)</h3>",
                unsafe_allow_html=True
            )

        st.write("**Detection Confidence:**", f"{confidence_percent}%")
        st.write("**Maximum Anomaly Score:**", round(incident["max_anomaly_score"], 4))

    st.markdown("---")

    # Risk Summary Section
    st.subheader("📊 Risk Summary")

    risk_data = incident["risk_summary"]

    risk_table = {
        "Metric": list(risk_data.keys()),
        "Value": list(risk_data.values())
    }

    st.table(risk_table)

    st.markdown("---")

    # Systems Involved
    st.subheader("🖥 Systems Involved")
    st.write(", ".join(incident["systems_involved"]))

    # MITRE Mapping
    if "mitre_mapping" in incident:
        st.subheader("🎯 MITRE ATT&CK Mapping")
        st.write(", ".join(incident["mitre_mapping"]))

    st.markdown("---")

    # Timeline Section
    st.subheader("🕒 Incident Timeline")

    for event in incident["timeline"]:
        st.write(f"{event['timestamp']}  →  {event['log_source']}")

    st.markdown("---")

    # Executive Summary
    st.subheader("📄 Executive Summary")

    st.write(
        f"This {incident['severity_level']} severity incident indicates potential "
        f"account compromise involving abnormal authentication behavior, privilege escalation, "
        f"and significant data transfer across {incident['systems_affected']} systems. "
        f"The detection engine identified {incident['anomalies_detected']} correlated anomalies "
        f"within a 30-minute analysis window."
    )

    st.markdown("---")

    # Role-based Playbook View
    if st.session_state.role in ["Admin", "SOC Analyst"]:
        st.subheader("🛠 Response Playbook")

        if incident.get("playbook"):
            st.markdown(incident["playbook"])
        else:
            st.warning("Playbook generation failed. Ensure Ollama is running.")

    else:
        st.info("Auditor role: Playbook access restricted (read-only mode).")

    st.markdown("---")

    # Export Button (Compliance Feature)
    st.subheader("📤 Export Incident Report")

    st.download_button(
        label="Download Incident Report (JSON)",
        data=json.dumps(incident, indent=4),
        file_name=f"{incident['incident_id']}_report.json",
        mime="application/json"
    )

else:
    st.success("No active incidents detected.")

