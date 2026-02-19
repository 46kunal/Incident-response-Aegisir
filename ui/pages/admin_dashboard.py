import streamlit as st
import json
import os

st.set_page_config(page_title="Admin Dashboard", layout="wide")

st.title("AegisIR System Usage Monitor")

log_path = "logs/system_usage.json"

if not os.path.exists(log_path):
    st.info("No system usage recorded yet.")
else:
    with open(log_path, "r") as f:
        usage_data = json.load(f)

    st.subheader("System Usage History")

    for record in usage_data[::-1]:
        st.write(
            f"🕒 {record['timestamp']} | "
            f"Logs Processed: {record['total_logs']} | "
            f"Incidents Detected: {record['incidents_detected']}"
        )

    total_runs = len(usage_data)
    total_incidents = sum(r["incidents_detected"] for r in usage_data)

    st.markdown("---")
    st.subheader("Summary Metrics")

    col1, col2 = st.columns(2)
    col1.metric("Total System Runs", total_runs)
    col2.metric("Total Incidents Generated", total_incidents)
