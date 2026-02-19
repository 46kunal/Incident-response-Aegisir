import streamlit as st
import json
from core.pipeline import run_detection_pipeline
from security.validator import (
    validate_file_size,
    validate_logs
)


# ----------------------------
# Page Config
# ----------------------------

st.set_page_config(
    page_title="AegisIR - Autonomous Incident Response",
    layout="wide"
)

st.title("🛡️ AegisIR - Autonomous Cyber Incident Response System")

# ----------------------------
# Session State Initialization
# ----------------------------

if "results" not in st.session_state:
    st.session_state.results = None

# ----------------------------
# Sidebar Upload Section
# ----------------------------

st.sidebar.header("📂 Upload Log Files")

auth_file = st.sidebar.file_uploader(
    "Upload Auth Logs (JSON)", type=["json"]
)
endpoint_file = st.sidebar.file_uploader(
    "Upload Endpoint Logs (JSON)", type=["json"]
)
network_file = st.sidebar.file_uploader(
    "Upload Network Logs (JSON)", type=["json"]
)

# ----------------------------
# Upload Handling + Start Scan
# ----------------------------

if auth_file and endpoint_file and network_file:

    try:
         # 🔐 File size validation
        validate_file_size(auth_file)
        validate_file_size(endpoint_file)
        validate_file_size(network_file)

        # 🔐 Safe JSON loading
        auth_logs = json.loads(auth_file.getvalue().decode("utf-8"))
        endpoint_logs = json.loads(endpoint_file.getvalue().decode("utf-8"))
        network_logs = json.loads(network_file.getvalue().decode("utf-8"))

        # 🔐 Schema & structure validation
        if isinstance(auth_logs, dict) and "logs" in auth_logs:
          auth_logs = auth_logs["logs"]

        validate_logs(auth_logs)
        validate_logs(endpoint_logs)
        validate_logs(network_logs)

        st.sidebar.success("✅ Logs uploaded successfully.")

        if st.sidebar.button("🚀 Start Security Scan"):

            with st.spinner(
                "🛡️ Correlating multi-system events... "
                "Running ML anomaly detection... "
                "Generating autonomous response playbook..."
            ):
                st.session_state.results = run_detection_pipeline(
                    auth_logs,
                    endpoint_logs,
                    network_logs
                )

            st.sidebar.success("✅ Scan completed successfully.")

    except Exception:
        st.sidebar.error("❌ Invalid log format. Please upload valid JSON files.")
        st.stop()

else:
    st.sidebar.info("Upload all three log files and click 'Start Security Scan'.")

# ----------------------------
# Stop Execution Until Scan Runs
# ----------------------------

results = st.session_state.results

if results is None:
    st.info("Upload logs and click 'Start Security Scan' to begin analysis.")
    st.stop()

# ----------------------------
# Top Summary Metrics
# ----------------------------

col1, col2, col3 = st.columns(3)

col1.metric("Total Logs Ingested", results["total_logs"])
col2.metric("Total Anomalies Detected", results["total_anomalies"])
col3.metric("Incidents Identified", len(results["incidents"]))

st.markdown("---")

# ----------------------------
# Anomaly Summary Section
# ----------------------------

st.markdown("### 📈 Anomaly Summary")

anomaly_percentage = round(
    (results["total_anomalies"] / results["total_logs"]) * 100, 2
)

st.write(
    f"Out of {results['total_logs']} logs ingested, "
    f"{results['total_anomalies']} were flagged as anomalous "
    f"({anomaly_percentage}%)."
)

st.markdown("---")

# ----------------------------
# Incident Details
# ----------------------------

if results["incidents"]:

    # 📊 Severity Distribution Chart
    st.subheader("📊 Incident Severity Distribution")

    severity_counts = {}
    for inc in results["incidents"]:
        level = inc["severity_level"]
        severity_counts[level] = severity_counts.get(level, 0) + 1

    import matplotlib.pyplot as plt
    plt.figure()
    plt.pie(severity_counts.values(), labels=severity_counts.keys(), autopct='%1.1f%%')
    st.pyplot(plt)

    st.markdown("---")

    incident = results["incidents"][0]

    st.subheader("🚨 Incident Overview")

    st.markdown(
        f"⚠️ The system detected a **{incident['severity_level']} severity security incident** "
        f"involving **{incident['user']}**, impacting "
        f"**{incident['systems_affected']} systems**."
    )

    st.write("**Incident ID:**", incident["incident_id"])
    st.write("**Affected User:**", incident["user"])
    st.write("**Incident Type:**", incident["incident_type"])

    # Severity Highlight
    if incident["severity_level"] == "Critical":
        st.error(f"Severity Level: {incident['severity_level']}")
    elif incident["severity_level"] == "High":
        st.warning(f"Severity Level: {incident['severity_level']}")
    else:
        st.info(f"Severity Level: {incident['severity_level']}")

    st.write("**Systems Involved:**", ", ".join(incident["systems_involved"]))
    st.write("**MITRE ATT&CK Mapping:**", ", ".join(incident["mitre_mapping"]))

    st.markdown("---")

    # 🔎 Explainable AI Section
    st.subheader("🔎 Explainable AI Insights")

    st.write("**Maximum Anomaly Score:**", round(incident["max_anomaly_score"], 4))

    st.write("**Risk Summary:**")
    st.json(incident["risk_summary"])

    st.markdown("---")

    # 🕒 Incident Timeline
    st.subheader("🕒 Incident Timeline")

    for event in incident["timeline"]:
        st.write(f"{event['timestamp']}  →  {event['log_source']}")

    st.markdown("---")

    # ----------------------------
    # Severity Breakdown
    # ----------------------------

    st.subheader("📊 Severity Breakdown")

    st.write("**Severity Score:**", incident["severity_score"])

    if "breakdown" in incident:
        st.json(incident["breakdown"])

    st.markdown("---")

    # ----------------------------
    # Automated Playbook Section
    # ----------------------------

    st.subheader("🛠 Automated Response Playbook")

    if "playbook" in incident and incident["playbook"]:
        with st.expander("View Full Response Playbook", expanded=True):
            st.markdown(incident["playbook"])
    else:
        st.warning("Playbook not generated. Ensure Ollama is running.")

else:
    st.success("No incidents detected.")