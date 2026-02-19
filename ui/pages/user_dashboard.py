import streamlit as st
import json
import sys
import os
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from core.pipeline import run_detection_pipeline
from security.validator import validate_file_size, validate_logs

st.set_page_config(page_title="AegisIR - User Dashboard", layout="wide")

st.title("AegisIR SOC Detection System")

# Sidebar upload
st.sidebar.header("Upload Log Files")

auth_file = st.sidebar.file_uploader("Auth Logs (JSON)", type=["json"])
endpoint_file = st.sidebar.file_uploader("Endpoint Logs (JSON)", type=["json"])
network_file = st.sidebar.file_uploader("Network Logs (JSON)", type=["json"])

if "results" not in st.session_state:
    st.session_state.results = None

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
            with st.spinner("Running AI Detection..."):
                st.session_state.results = run_detection_pipeline(
                    auth_logs,
                    endpoint_logs,
                    network_logs
                )

                # 🔥 Log system usage
                usage_record = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "incidents_detected": len(st.session_state.results["incidents"]),
                    "total_logs": st.session_state.results["total_logs"]
                }

                os.makedirs("logs", exist_ok=True)

                log_path = "logs/system_usage.json"

                if os.path.exists(log_path):
                    with open(log_path, "r") as f:
                        data = json.load(f)
                else:
                    data = []

                data.append(usage_record)

                with open(log_path, "w") as f:
                    json.dump(data, f, indent=4)

    except Exception as e:
        st.error(str(e))

if st.session_state.results:

    results = st.session_state.results

    st.markdown("---")

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Logs", results["total_logs"])
    col2.metric("Anomalies", results["total_anomalies"])
    col3.metric("Incidents", len(results["incidents"]))

    st.markdown("---")

    if results["incidents"]:

        incident_ids = [inc["incident_id"] for inc in results["incidents"]]
        selected_id = st.selectbox("Select Incident", incident_ids)

        incident = next(inc for inc in results["incidents"] if inc["incident_id"] == selected_id)

        severity_map = {
            "Low": 25,
            "Medium": 50,
            "High": 75,
            "Critical": 100
        }

        severity_percent = severity_map.get(incident["severity_level"], 0)
        confidence_percent = round(abs(incident["max_anomaly_score"]) * 100, 2)

        st.subheader("Incident Overview")
        st.write("User:", incident["user"])
        st.write("Severity:", f"{incident['severity_level']} ({severity_percent}%)")
        st.write("Detection Confidence:", f"{confidence_percent}%")
        st.write("Incident Type:", incident["incident_type"])
        st.write("Start Time:", incident["start_time"])

        st.markdown("---")

        st.subheader("Risk Summary")
        st.json(incident["risk_summary"])

        st.markdown("---")

        st.subheader("Timeline")
        for event in incident["timeline"]:
            st.write(f"{event['timestamp']} → {event['log_source']}")

        st.markdown("---")

        if incident.get("playbook"):
            st.subheader("Response Playbook")
            st.markdown(incident["playbook"])
