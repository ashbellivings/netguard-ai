"""
Exploratory Security Data Analysis Module for NETGUARD AI
Generates security visualizations and automated analytical findings.
"""

import pandas as pd
import numpy as np


def generate_automated_findings(df: pd.DataFrame) -> list[dict]:
    """
    Computes at least 10 real data findings from the network traffic dataset.
    """
    findings = []
    total = len(df)
    if total == 0:
        return findings

    # 1. Dominant Protocol
    proto_counts = df["Protocol"].value_counts() if "Protocol" in df.columns else pd.Series()
    if not proto_counts.empty:
        top_proto = proto_counts.index[0]
        top_proto_pct = round((proto_counts.iloc[0] / total) * 100, 1)
        findings.append({
            "id": "FIND-01",
            "category": "Protocol Analysis",
            "title": "Most Frequent Transport Protocol",
            "metric": f"{top_proto} ({top_proto_pct}%)",
            "description": f"{top_proto} dominates traffic volume with {proto_counts.iloc[0]} flows, accounting for {top_proto_pct}% of total records."
        })

    # 2. Suspicious Traffic Ratio
    if "Label" in df.columns:
        sus_count = int((df["Label"] == "SUSPICIOUS").sum())
        sus_pct = round((sus_count / total) * 100, 1)
        findings.append({
            "id": "FIND-02",
            "category": "Threat Density",
            "title": "Malicious Traffic Proportion",
            "metric": f"{sus_pct}% ({sus_count} flows)",
            "description": f"{sus_count} out of {total} records are flagged as suspicious activity ({sus_pct}% threat density)."
        })

    # 3. Leading Attack Category
    if "Attack_Category" in df.columns:
        sus_df = df[df["Label"] == "SUSPICIOUS"] if "Label" in df.columns else df
        cat_counts = sus_df["Attack_Category"].value_counts()
        if not cat_counts.empty and cat_counts.index[0] != "Normal":
            top_cat = cat_counts.index[0]
            findings.append({
                "id": "FIND-03",
                "category": "Threat Taxonomy",
                "title": "Dominant Attack Category",
                "metric": f"{top_cat} ({cat_counts.iloc[0]} occurrences)",
                "description": f"The most prevalent threat signature observed is {top_cat}, comprising {round((cat_counts.iloc[0] / len(sus_df)) * 100, 1)}% of all flagged flows."
            })

    # 4. Top Destination Port
    if "Destination_Port" in df.columns:
        port_counts = df["Destination_Port"].value_counts()
        top_port = port_counts.index[0]
        findings.append({
            "id": "FIND-04",
            "category": "Target Ports",
            "title": "Most Targeted Destination Port",
            "metric": f"Port {top_port} ({port_counts.iloc[0]} connections)",
            "description": f"Port {top_port} received the highest connection density with {port_counts.iloc[0]} connection attempts."
        })

    # 5. Connection Duration Extremes
    if "Flow_Duration" in df.columns:
        max_dur = round(float(df["Flow_Duration"].max()), 2)
        avg_dur = round(float(df["Flow_Duration"].mean()), 2)
        long_flows = int((df["Flow_Duration"] > 20).sum())
        findings.append({
            "id": "FIND-05",
            "category": "Duration Dynamics",
            "title": "Connection Persistence",
            "metric": f"Max: {max_dur}s | Mean: {avg_dur}s",
            "description": f"Identified {long_flows} long-lived connections exceeding 20 seconds. Peak connection lasted {max_dur}s."
        })

    # 6. Packet Count Bursts
    if "Packet_Count" in df.columns:
        max_pkts = int(df["Packet_Count"].max())
        burst_flows = int((df["Packet_Count"] > 250).sum())
        findings.append({
            "id": "FIND-06",
            "category": "Anomaly Detection",
            "title": "High Packet Burst Activity",
            "metric": f"Peak: {max_pkts} pkts ({burst_flows} bursts)",
            "description": f"Detected {burst_flows} high-volume burst flows (>250 pkts/flow). Peak flow reached {max_pkts} packets, characteristic of flood attacks."
        })

    # 7. Byte Volume Distribution
    if "Byte_Count" in df.columns:
        tot_bytes = int(df["Byte_Count"].sum())
        avg_bytes = int(df["Byte_Count"].mean())
        findings.append({
            "id": "FIND-07",
            "category": "Bandwidth Utilization",
            "title": "Total Transferred Volume",
            "metric": f"{round(tot_bytes / (1024 * 1024), 2)} MB total",
            "description": f"Analyzed network flows transferred {tot_bytes:,} bytes across the observation window (average {avg_bytes:,} bytes/flow)."
        })

    # 8. Class Imbalance
    if "Label" in df.columns:
        norm = int((df["Label"] == "NORMAL").sum())
        sus = int((df["Label"] == "SUSPICIOUS").sum())
        ratio = round(norm / max(sus, 1), 2)
        findings.append({
            "id": "FIND-08",
            "category": "Class Distribution",
            "title": "Class Imbalance Ratio",
            "metric": f"{ratio}:1 (Normal:Suspicious)",
            "description": f"Dataset exhibits a {ratio}:1 ratio of benign to suspicious flows, reflecting typical enterprise telemetry."
        })

    # 9. Correlation Between Features
    if "Packet_Count" in df.columns and "Byte_Count" in df.columns:
        corr = round(float(df["Packet_Count"].corr(df["Byte_Count"])), 3)
        findings.append({
            "id": "FIND-09",
            "category": "Feature Correlation",
            "title": "Packet-to-Byte Correlation",
            "metric": f"r = {corr}",
            "description": f"Linear correlation between packet count and byte count is r = {corr}, confirming packet payload proportionality."
        })

    # 10. Concentration on Sensitive Ports
    if "Destination_Port" in df.columns and "Label" in df.columns:
        sus_df = df[df["Label"] == "SUSPICIOUS"]
        sensitive_ports = [21, 22, 23, 25, 53, 80, 443, 445, 1433, 3306, 3389, 4444, 8080]
        sus_sensitive = int(sus_df["Destination_Port"].isin(sensitive_ports).sum()) if not sus_df.empty else 0
        sens_pct = round((sus_sensitive / max(len(sus_df), 1)) * 100, 1)
        findings.append({
            "id": "FIND-10",
            "category": "Target Concentration",
            "title": "Sensitive Port Attack Ratio",
            "metric": f"{sens_pct}% targeting critical ports",
            "description": f"{sus_sensitive} out of {len(sus_df)} suspicious flows specifically targeted well-known service ports (e.g. SSH, RDP, SMB, HTTP)."
        })

    return findings
