"""
NETGUARD AI: AI-Based Network Intrusion Detection & Security Monitoring System
Main Streamlit Application Entry Point
"""

import os
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

from config import APP_NAME, TAGLINE, DB_PATH, SAMPLE_DATA_PATH
from modules.data_loader import auto_map_columns, assess_data_quality, load_demo_dataset
from modules.preprocessing import preprocess_network_data
from modules.exploratory_analysis import generate_automated_findings
from modules.intrusion_detection import train_models, run_model_inference
from modules.model_evaluation import evaluate_models
from modules.alert_manager import (
    sync_alerts_from_predictions,
    get_all_alerts,
    update_alert_status,
    get_investigation_notes
)
from modules.incident_manager import get_incident_playbook
from modules.report_generator import generate_executive_text_report

# Page Configuration
st.set_page_config(
    page_title=f"{APP_NAME} - SOC Intrusion Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom SOC Dark Theme CSS
st.markdown("""
<style>
    .reportview-container { background: #030712; }
    .main .block-container { padding-top: 1.5rem; padding-bottom: 2rem; }
    .kpi-card {
        background-color: #0b1329;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 16px;
        text-align: left;
    }
    .kpi-title { font-size: 11px; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.05em; }
    .kpi-val { font-size: 26px; font-weight: 700; color: #f8fafc; margin-top: 4px; font-family: monospace; }
</style>
""", unsafe_allow_html=True)

# Initialize Session State
if "raw_df" not in st.session_state:
    st.session_state["raw_df"] = None
if "cleaned_df" not in st.session_state:
    st.session_state["cleaned_df"] = None
if "models" not in st.session_state:
    st.session_state["models"] = None
if "eval_metrics" not in st.session_state:
    st.session_state["eval_metrics"] = None
if "predictions_df" not in st.session_state:
    st.session_state["predictions_df"] = None
if "dataset_name" not in st.session_state:
    st.session_state["dataset_name"] = "No Dataset Loaded"


# Sidebar Navigation
st.sidebar.markdown(f"## 🛡️ {APP_NAME}")
st.sidebar.caption(TAGLINE)
st.sidebar.markdown("---")

nav_choice = st.sidebar.radio(
    "SOC NAVIGATION",
    [
        "1. Security Overview",
        "2. Traffic Data Management",
        "3. Data Preprocessing",
        "4. Exploratory Analysis",
        "5. AI Intrusion Detection",
        "6. Model Evaluation",
        "7. Security Alerts",
        "8. Incident Workspace",
        "9. Threat Intelligence",
        "10. Security Reports",
        "11. Packet & Log Integrations"
    ]
)

st.sidebar.markdown("---")
# Quick Demo Loader in Sidebar
if st.sidebar.button("⚡ Load Demo Dataset", use_container_width=True):
    demo_df = load_demo_dataset(SAMPLE_DATA_PATH)
    st.session_state["raw_df"] = demo_df
    st.session_state["dataset_name"] = "Synthetic Demo Dataset (sample_network_traffic.csv)"
    st.sidebar.success("Demo dataset loaded successfully!")
    st.rerun()

st.sidebar.caption("NETGUARD AI · B.Sc. CS Capstone 2026")


# ==============================================================================
# MODULE 1: SECURITY OVERVIEW
# ==============================================================================
if nav_choice == "1. Security Overview":
    st.title("🛡️ SOC Security Monitoring Overview")
    st.caption(f"Active Monitored Dataset: {st.session_state['dataset_name']}")

    if st.session_state["raw_df"] is None:
        st.info("No network traffic dataset loaded yet. Click below to load demo data or upload via Data Management.")
        if st.button("Load Demo Dataset Now", type="primary"):
            demo_df = load_demo_dataset(SAMPLE_DATA_PATH)
            st.session_state["raw_df"] = demo_df
            st.session_state["dataset_name"] = "Synthetic Demo Dataset"
            st.rerun()
    else:
        df = st.session_state["raw_df"]
        total_flows = len(df)
        normal_flows = int((df["Label"] == "NORMAL").sum()) if "Label" in df.columns else total_flows
        sus_flows = int((df["Label"] == "SUSPICIOUS").sum()) if "Label" in df.columns else 0

        alerts_df = get_all_alerts(DB_PATH)
        crit_count = int((alerts_df["severity"] == "CRITICAL").sum()) if not alerts_df.empty else 0

        acc_str = "Pending ML"
        if st.session_state["eval_metrics"] and "random_forest" in st.session_state["eval_metrics"]:
            acc_str = f"{round(st.session_state['eval_metrics']['random_forest']['accuracy'] * 100, 1)}%"

        # KPI Row
        k1, k2, k3, k4, k5, k6 = st.columns(6)
        with k1:
            st.metric("Total Flows", f"{total_flows:,}")
        with k2:
            st.metric("Normal Traffic", f"{normal_flows:,}")
        with k3:
            st.metric("Suspicious Traffic", f"{sus_flows:,}", delta=f"{round((sus_flows/max(total_flows, 1))*100, 1)}%", delta_color="inverse")
        with k4:
            st.metric("Security Alerts", f"{len(alerts_df):,}")
        with k5:
            st.metric("Critical Alerts", f"{crit_count:,}")
        with k6:
            st.metric("Detection Accuracy", acc_str)

        st.markdown("---")

        # Overview Charts
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Traffic Classification Breakdown")
            fig_pie = px.pie(
                values=[normal_flows, sus_flows],
                names=["Normal", "Suspicious"],
                color=["Normal", "Suspicious"],
                color_discrete_map={"Normal": "#10b981", "Suspicious": "#ef4444"},
                hole=0.45
            )
            fig_pie.update_layout(template="plotly_dark", margin=dict(t=20, b=20, l=20, r=20))
            st.plotly_chart(fig_pie, use_container_width=True)

        with c2:
            st.subheader("Alerts by Severity")
            if not alerts_df.empty:
                sev_counts = alerts_df["severity"].value_counts().reset_index()
                sev_counts.columns = ["Severity", "Count"]
                fig_bar = px.bar(
                    sev_counts, x="Severity", y="Count",
                    color="Severity",
                    color_discrete_map={"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#16a34a"}
                )
                fig_bar.update_layout(template="plotly_dark", margin=dict(t=20, b=20, l=20, r=20))
                st.plotly_chart(fig_bar, use_container_width=True)
            else:
                st.info("Run AI Intrusion Detection to generate and view alerts by severity.")

        c3, c4 = st.columns(2)
        with c3:
            st.subheader("Traffic Volume by Protocol")
            if "Protocol" in df.columns:
                p_counts = df["Protocol"].value_counts().reset_index()
                p_counts.columns = ["Protocol", "Flows"]
                fig_proto = px.bar(p_counts, x="Protocol", y="Flows", color="Protocol", color_discrete_sequence=px.colors.qualitative.Safe)
                fig_proto.update_layout(template="plotly_dark", margin=dict(t=20, b=20, l=20, r=20))
                st.plotly_chart(fig_proto, use_container_width=True)

        with c4:
            st.subheader("Top Suspicious Source IPs")
            if "Source_IP" in df.columns and "Label" in df.columns:
                sus_ips = df[df["Label"] == "SUSPICIOUS"]["Source_IP"].value_counts().head(5).reset_index()
                sus_ips.columns = ["Source IP", "Alert Count"]
                fig_ips = px.bar(sus_ips, x="Alert Count", y="Source IP", orientation='h', color_discrete_sequence=["#ef4444"])
                fig_ips.update_layout(template="plotly_dark", margin=dict(t=20, b=20, l=20, r=20))
                st.plotly_chart(fig_ips, use_container_width=True)


# ==============================================================================
# MODULE 2: NETWORK TRAFFIC DATA MANAGEMENT
# ==============================================================================
elif nav_choice == "2. Traffic Data Management":
    st.title("📂 Network Traffic Data Management")
    st.write("Upload CSV network captures or inspect currently loaded telemetry records.")

    uploaded_file = st.file_uploader(
        "Upload Network Traffic Capture (.csv, .tsv, .txt - CIC-IDS2017, UNSW-NB15, Suricata, Zeek, etc.)",
        type=["csv", "tsv", "txt"]
    )
    if uploaded_file is not None:
        try:
            raw_input_df = pd.read_csv(uploaded_file, sep=None, engine='python')
            mapped_df, mapping_used, missing_req = auto_map_columns(raw_input_df)
            st.session_state["raw_df"] = mapped_df
            st.session_state["dataset_name"] = uploaded_file.name
            st.success(f"Successfully loaded {uploaded_file.name} ({len(mapped_df)} records) with auto-delimiter resolution!")
            if missing_req:
                st.warning(f"Note: Some standard columns were not matched: {missing_req}")
        except Exception as e:
            st.error(f"Error parsing uploaded CSV: {e}")

    if st.session_state["raw_df"] is not None:
        df = st.session_state["raw_df"]
        quality = assess_data_quality(df)

        q1, q2, q3, q4 = st.columns(4)
        q1.metric("Total Records", f"{quality['total_rows']:,}")
        q2.metric("Total Features", f"{quality['total_columns']}")
        q3.metric("Missing Values", f"{quality['missing_values']:,}")
        q4.metric("Data Quality Score", f"{quality['quality_score']}%")

        st.subheader("Data Quality Inspection")
        c1, c2 = st.columns(2)
        with c1:
            st.write(f"- **Duplicate Records Detected:** {quality['duplicates']}")
            st.write(f"- **Invalid Numerical Values:** {quality['invalid_numerics']}")
        with c2:
            st.write(f"- **Inconsistent Labels:** {quality['inconsistent_labels']}")
            st.write(f"- **Active Dataset:** `{st.session_state['dataset_name']}`")

        st.subheader("Network Traffic Preview (Top 15 Records)")
        st.dataframe(df.head(15), use_container_width=True)


# ==============================================================================
# MODULE 3: DATA PREPROCESSING
# ==============================================================================
elif nav_choice == "3. Data Preprocessing":
    st.title("⚙️ Data Preprocessing & Pipeline")
    st.write("Clean network traffic, encode protocols, scale numerical metrics, and split data without leakage.")

    if st.session_state["raw_df"] is None:
        st.warning("Please load or upload a dataset first.")
    else:
        df = st.session_state["raw_df"]

        col1, col2 = st.columns([1, 2])
        with col1:
            split_ratio = st.slider("Train / Test Split Ratio", min_value=0.5, max_value=0.9, value=0.75, step=0.05)
            seed_val = st.number_input("Reproducible Random Seed", value=42, step=1)
            run_clean = st.button("Execute Data Preprocessing", type="primary")

        if run_clean or st.session_state["cleaned_df"] is not None:
            if run_clean:
                with st.spinner("Processing network flow features..."):
                    cleaned_df, X_train, X_test, y_train, y_test, train_df, test_df, scaler, summary = preprocess_network_data(
                        df, train_ratio=split_ratio, random_state=int(seed_val)
                    )
                    st.session_state["cleaned_df"] = cleaned_df
                    st.session_state["X_train"] = X_train
                    st.session_state["X_test"] = X_test
                    st.session_state["y_train"] = y_train
                    st.session_state["y_test"] = y_test
                    st.session_state["train_df"] = train_df
                    st.session_state["test_df"] = test_df
                    st.session_state["prep_summary"] = summary
                st.success("Data preprocessing completed successfully!")

            summary = st.session_state.get("prep_summary", {})
            st.subheader("Preprocessing Pipeline Summary")
            p1, p2, p3, p4 = st.columns(4)
            p1.metric("Training Flows", f"{summary.get('train_rows', 0):,}")
            p2.metric("Testing Flows", f"{summary.get('test_rows', 0):,}")
            p3.metric("Duplicates Removed", f"{summary.get('duplicates_removed', 0)}")
            p4.metric("Class Imbalance", f"{summary.get('imbalance_ratio', 1.0)}:1")

            st.markdown("#### Data Leakage Safeguards")
            for item in summary.get("leakage_safeguards", []):
                st.write(f"✅ {item}")

            st.markdown("#### Preprocessed Feature Matrix Sample")
            st.dataframe(st.session_state["X_train"].head(10), use_container_width=True)


# ==============================================================================
# MODULE 4: EXPLORATORY SECURITY DATA ANALYSIS
# ==============================================================================
elif nav_choice == "4. Exploratory Analysis":
    st.title("🔍 Exploratory Security Data Analysis")
    st.write("Examine attack distributions, connection durations, packet volumes, and dynamic security findings.")

    if st.session_state["raw_df"] is None:
        st.warning("Please load or upload a dataset first.")
    else:
        df = st.session_state["raw_df"]
        findings = generate_automated_findings(df)

        st.subheader("10 Automated Security Findings")
        for f in findings:
            with st.expander(f"📌 {f['title']} — {f['metric']}"):
                st.write(f['description'])

        st.markdown("---")
        st.subheader("Security Visualizations")

        c1, c2 = st.columns(2)
        with c1:
            st.markdown("##### 1. Connection Duration Distribution")
            if "Flow_Duration" in df.columns:
                fig_dur = px.histogram(df, x="Flow_Duration", nbins=30, color_discrete_sequence=["#38bdf8"])
                fig_dur.update_layout(template="plotly_dark", margin=dict(t=10, b=10, l=10, r=10))
                st.plotly_chart(fig_dur, use_container_width=True)

        with c2:
            st.markdown("##### 2. Packet Count Anomalies")
            if "Packet_Count" in df.columns:
                fig_pkts = px.box(df, y="Packet_Count", color_discrete_sequence=["#f59e0b"])
                fig_pkts.update_layout(template="plotly_dark", margin=dict(t=10, b=10, l=10, r=10))
                st.plotly_chart(fig_pkts, use_container_width=True)

        c3, c4 = st.columns(2)
        with c3:
            st.markdown("##### 3. Byte Count vs Flow Duration")
            if "Byte_Count" in df.columns and "Flow_Duration" in df.columns:
                fig_scat = px.scatter(df, x="Flow_Duration", y="Byte_Count", color="Label" if "Label" in df.columns else None,
                                      color_discrete_map={"NORMAL": "#10b981", "SUSPICIOUS": "#ef4444"})
                fig_scat.update_layout(template="plotly_dark", margin=dict(t=10, b=10, l=10, r=10))
                st.plotly_chart(fig_scat, use_container_width=True)

        with c4:
            st.markdown("##### 4. Destination Port Frequencies")
            if "Destination_Port" in df.columns:
                top_p = df["Destination_Port"].value_counts().head(8).reset_index()
                top_p.columns = ["Port", "Count"]
                top_p["Port"] = top_p["Port"].astype(str)
                fig_port = px.bar(top_p, x="Port", y="Count", color_discrete_sequence=["#a855f7"])
                fig_port.update_layout(template="plotly_dark", margin=dict(t=10, b=10, l=10, r=10))
                st.plotly_chart(fig_port, use_container_width=True)


# ==============================================================================
# MODULE 5: AI-BASED INTRUSION DETECTION
# ==============================================================================
elif nav_choice == "5. AI Intrusion Detection":
    st.title("🤖 AI-Based Intrusion Detection Engine")
    st.write("Train machine learning algorithms and run flow classification.")

    if "X_train" not in st.session_state:
        st.warning("Please run Module 3 (Data Preprocessing) first.")
    else:
        if st.button("Train All Machine Learning Models", type="primary"):
            with st.spinner("Training Logistic Regression, Decision Tree, Random Forest & Isolation Forest..."):
                models = train_models(st.session_state["X_train"], st.session_state["y_train"])
                st.session_state["models"] = models
                metrics = evaluate_models(models, st.session_state["X_test"], st.session_state["y_test"])
                st.session_state["eval_metrics"] = metrics
            st.success("All models trained and evaluated successfully!")

        if st.session_state["models"] is not None:
            models = st.session_state["models"]
            sel_algo = st.selectbox(
                "Select Model for Detection Inference",
                ["random_forest", "decision_tree", "logistic_regression", "isolation_forest"]
            )

            if st.button("Run Intrusion Detection on Flows"):
                with st.spinner(f"Running detection with {sel_algo}..."):
                    eval_df = st.session_state["cleaned_df"]
                    X_all = pd.concat([st.session_state["X_train"], st.session_state["X_test"]]).loc[eval_df.index]
                    pred_df = run_model_inference(sel_algo, models[sel_algo], X_all, eval_df)
                    st.session_state["predictions_df"] = pred_df

                    # Sync alerts to SQLite DB
                    new_alerts = sync_alerts_from_predictions(pred_df, DB_PATH)
                    st.success(f"Detection complete! Generated {new_alerts} new security alerts in SOC database.")

            if st.session_state["predictions_df"] is not None:
                st.subheader("Flow Detection Results")
                st.dataframe(
                    st.session_state["predictions_df"][["Timestamp", "Source_IP", "Destination_IP", "Destination_Port", "Protocol", "Predicted_Label", "Confidence", "Severity", "Detection_Reason"]].head(25),
                    use_container_width=True
                )


# ==============================================================================
# MODULE 6: MODEL PERFORMANCE EVALUATION
# ==============================================================================
elif nav_choice == "6. Model Evaluation":
    st.title("📊 Model Performance Evaluation")
    st.write("Compare supervised classifiers and inspect confusion matrices.")

    if st.session_state["eval_metrics"] is None:
        st.warning("Please train models in Module 5 first.")
    else:
        metrics = st.session_state["eval_metrics"]

        comp_data = []
        for k, v in metrics.items():
            comp_data.append({
                "Algorithm": v["name"],
                "Accuracy": f"{v['accuracy']*100:.1f}%",
                "Precision": f"{v['precision']*100:.1f}%",
                "Recall": f"{v['recall']*100:.1f}%",
                "F1-Score": f"{v['f1_score']*100:.1f}%",
                "False Positive Rate": f"{v['false_positive_rate']*100:.1f}%",
                "False Negative Rate": f"{v['false_negative_rate']*100:.1f}%",
            })
        st.dataframe(pd.DataFrame(comp_data), use_container_width=True)

        st.subheader("Confusion Matrix Inspector")
        algo_choice = st.selectbox("Select Model", list(metrics.keys()))
        cm = metrics[algo_choice]["confusion_matrix"]
        
        c1, c2 = st.columns(2)
        with c1:
            st.write(f"- **True Positives (Attacks Correctly Detected):** {cm['tp']}")
            st.write(f"- **True Negatives (Normal Correctly Passed):** {cm['tn']}")
        with c2:
            st.write(f"- **False Positives (Normal Flagged as Attack):** {cm['fp']}")
            st.write(f"- **False Negatives (Attacks Missed by Model):** {cm['fn']}")


# ==============================================================================
# MODULE 7: SECURITY ALERT MANAGEMENT
# ==============================================================================
elif nav_choice == "7. Security Alerts":
    st.title("🚨 SOC Security Alert Management")
    st.write("Triage alerts, search by IP/protocol, and manage analyst workflow.")

    alerts_df = get_all_alerts(DB_PATH)
    if alerts_df.empty:
        st.info("No security alerts generated yet. Run Module 5 (AI Intrusion Detection) to generate alerts.")
    else:
        f1, f2, f3 = st.columns(3)
        with f1:
            sev_filter = st.multiselect("Filter by Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        with f2:
            status_filter = st.multiselect("Filter by Status", ["New", "Investigating", "Resolved", "False Positive"], default=["New", "Investigating", "Resolved", "False Positive"])
        with f3:
            ip_search = st.text_input("Search Source/Target IP", "")

        filtered_alerts = alerts_df.copy()
        if sev_filter:
            filtered_alerts = filtered_alerts[filtered_alerts["severity"].isin(sev_filter)]
        if status_filter:
            filtered_alerts = filtered_alerts[filtered_alerts["status"].isin(status_filter)]
        if ip_search:
            filtered_alerts = filtered_alerts[filtered_alerts["source_ip"].str.contains(ip_search) | filtered_alerts["destination_ip"].str.contains(ip_search)]

        st.dataframe(filtered_alerts[["id", "timestamp", "source_ip", "destination_ip", "destination_port", "protocol", "predicted_category", "severity", "status"]], use_container_width=True)


# ==============================================================================
# MODULE 8: INCIDENT MANAGEMENT WORKSPACE
# ==============================================================================
elif nav_choice == "8. Incident Workspace":
    st.title("🔬 Junior SOC Analyst Incident Workspace")
    alerts_df = get_all_alerts(DB_PATH)

    if alerts_df.empty:
        st.info("No alerts available to investigate.")
    else:
        selected_id = st.selectbox("Select Incident / Alert ID", alerts_df["id"].tolist())
        alert_row = alerts_df[alerts_df["id"] == selected_id].iloc[0]

        st.subheader(f"Incident Details: {alert_row['id']}")
        c1, c2, c3 = st.columns(3)
        c1.write(f"**Source:** `{alert_row['source_ip']}:{alert_row['source_port']}`")
        c2.write(f"**Target:** `{alert_row['destination_ip']}:{alert_row['destination_port']}` ({alert_row['protocol']})")
        c3.write(f"**Severity:** `{alert_row['severity']}` | **Status:** `{alert_row['status']}`")

        st.info(f"**Detection Rationale:** {alert_row['detection_reason']}")

        st.markdown("#### SOC Playbook Investigation Steps")
        playbook = get_incident_playbook(alert_row["predicted_category"])
        for step in playbook:
            st.write(step)

        st.markdown("#### Update Incident Status & Analyst Notes")
        new_status = st.selectbox("Update Status", ["New", "Investigating", "Resolved", "False Positive"], index=["New", "Investigating", "Resolved", "False Positive"].index(alert_row["status"]))
        note_text = st.text_area("Analyst Investigation Note", "")
        if st.button("Save Incident Record", type="primary"):
            update_alert_status(DB_PATH, alert_row["id"], new_status, note_text)
            st.success("Incident record updated!")
            st.rerun()

        st.markdown("#### Investigation History Log")
        notes = get_investigation_notes(DB_PATH, alert_row["id"])
        for n in notes:
            st.write(f"**{n['author']}** ({n['timestamp']}) [Status: {n['status_change']}]: {n['note']}")


# ==============================================================================
# MODULE 9: THREAT INTELLIGENCE
# ==============================================================================
elif nav_choice == "9. Threat Intelligence":
    st.title("🌐 Threat Intelligence & Attack Profiling")
    alerts_df = get_all_alerts(DB_PATH)

    if alerts_df.empty:
        st.info("No threat data available. Run intrusion detection to populate.")
    else:
        st.subheader("Attack Category Distribution")
        cat_counts = alerts_df["predicted_category"].value_counts().reset_index()
        cat_counts.columns = ["Attack Category", "Count"]
        fig = px.pie(cat_counts, names="Attack Category", values="Count", hole=0.4)
        fig.update_layout(template="plotly_dark")
        st.plotly_chart(fig, use_container_width=True)


# ==============================================================================
# MODULE 10: SECURITY REPORTS
# ==============================================================================
elif nav_choice == "10. Security Reports":
    st.title("📄 Security Investigation Report Generator")
    alerts_df = get_all_alerts(DB_PATH)

    if st.session_state["raw_df"] is None:
        st.warning("Please load a dataset first.")
    else:
        raw_df = st.session_state["raw_df"]
        total = len(raw_df)
        norm = int((raw_df["Label"] == "NORMAL").sum()) if "Label" in raw_df.columns else total
        sus = int((raw_df["Label"] == "SUSPICIOUS").sum()) if "Label" in raw_df.columns else 0

        findings = generate_automated_findings(raw_df)
        metrics = st.session_state.get("eval_metrics", None)

        report_text = generate_executive_text_report(
            st.session_state["dataset_name"],
            total,
            norm,
            sus,
            alerts_df,
            metrics,
            findings
        )

        st.text_area("Generated SOC Report Preview", report_text, height=350)
        st.download_button(
            "Download Executive Report (TXT)",
            data=report_text,
            file_name="NETGUARD_AI_SOC_Report.txt",
            mime="text/plain"
        )
        if not alerts_df.empty:
            st.download_button(
                "Download Security Alerts (CSV)",
                data=alerts_df.to_csv(index=False),
                file_name="netguard_security_alerts.csv",
                mime="text/csv"
            )


# ==============================================================================
# MODULE 11: PACKET & LOG INTEGRATIONS
# ==============================================================================
elif nav_choice == "11. Packet & Log Integrations":
    st.title("🔌 Packet Capture & Log Integrations")
    st.markdown("""
    ### Wireshark Integration
    Export PCAP files into NETGUARD AI compatible CSV via `tshark`:
    ```bash
    tshark -r capture.pcap -T fields -E header=y -E separator=, \\
      -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \\
      -e ip.proto -e frame.len > netguard_export.csv
    ```

    ### Zeek (Bro) Integration
    Zeek connection logs (`conn.log`) can be converted to CSV using Zeek's `zeek-cut`:
    ```bash
    cat conn.log | zeek-cut ts id.orig_h id.resp_h id.orig_p id.resp_p proto duration orig_pkts orig_bytes > conn.tsv
    ```

    ### Suricata Integration
    Suricata `eve.json` alert files can be converted to NETGUARD schema using Python's `json` module.
    """)
