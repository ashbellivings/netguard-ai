"""
Security Report Generation Module for NETGUARD AI
Generates downloadable CSV audit exports and executive SOC incident summary reports.
"""

from datetime import datetime
import pandas as pd


def generate_executive_text_report(
    dataset_name: str,
    total_flows: int,
    normal_flows: int,
    suspicious_flows: int,
    alerts_df: pd.DataFrame,
    metrics_dict: dict = None,
    findings: list[dict] = None
) -> str:
    """
    Generates a structured, professional text/markdown executive report for B.Sc. submission.
    """
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    crit_count = int((alerts_df["severity"] == "CRITICAL").sum()) if not alerts_df.empty else 0
    high_count = int((alerts_df["severity"] == "HIGH").sum()) if not alerts_df.empty else 0
    med_count = int((alerts_df["severity"] == "MEDIUM").sum()) if not alerts_df.empty else 0
    low_count = int((alerts_df["severity"] == "LOW").sum()) if not alerts_df.empty else 0

    resolved_count = int((alerts_df["status"] == "Resolved").sum()) if not alerts_df.empty else 0
    investigating_count = int((alerts_df["status"] == "Investigating").sum()) if not alerts_df.empty else 0
    fp_count = int((alerts_df["status"] == "False Positive").sum()) if not alerts_df.empty else 0
    new_count = int((alerts_df["status"] == "New").sum()) if not alerts_df.empty else 0

    lines = [
        "=" * 78,
        "NETGUARD AI - EXECUTIVE CYBERSECURITY INCIDENT & MONITORING REPORT",
        "=" * 78,
        f"Generated: {now_str}",
        f"Dataset:   {dataset_name}",
        f"Project:   Final-Year B.Sc. Computer Science Cybersecurity Capstone",
        "-" * 78,
        "",
        "1. EXECUTIVE OVERVIEW & TRAFFIC SUMMARY",
        f"  * Total Network Flows Monitored: {total_flows:,}",
        f"  * Normal / Benign Traffic:       {normal_flows:,} ({round((normal_flows/max(total_flows, 1))*100, 1)}%)",
        f"  * Suspicious / Malicious Flows:  {suspicious_flows:,} ({round((suspicious_flows/max(total_flows, 1))*100, 1)}%)",
        f"  * Total Security Alerts Logged:  {len(alerts_df)}",
        "",
        "2. ALERT SEVERITY BREAKDOWN",
        f"  * CRITICAL Severity Alerts:      {crit_count}",
        f"  * HIGH Severity Alerts:          {high_count}",
        f"  * MEDIUM Severity Alerts:        {med_count}",
        f"  * LOW Severity Alerts:           {low_count}",
        "",
        "3. SOC INCIDENT INVESTIGATION STATUS",
        f"  * New / Unassigned:              {new_count}",
        f"  * Active Investigation:          {investigating_count}",
        f"  * Resolved Incidents:            {resolved_count}",
        f"  * False Positives Confirmed:     {fp_count}",
        "",
        "4. MACHINE LEARNING DETECTION BENCHMARKS",
    ]

    if metrics_dict:
        for m_key, m in metrics_dict.items():
            lines.append(f"  * {m['name']}:")
            lines.append(f"      - Accuracy:  {round(m['accuracy']*100, 2)}%")
            lines.append(f"      - Precision: {round(m['precision']*100, 2)}%")
            lines.append(f"      - Recall:    {round(m['recall']*100, 2)}%")
            lines.append(f"      - F1-Score:  {round(m['f1_score']*100, 2)}%")
            lines.append(f"      - FP Rate:   {round(m['false_positive_rate']*100, 2)}%")
            lines.append(f"      - FN Rate:   {round(m['false_negative_rate']*100, 2)}%")
    else:
        lines.append("  * Supervised benchmarks not available (unlabeled or pending evaluation).")

    lines.extend([
        "",
        "5. AUTOMATED SECURITY DATA FINDINGS",
    ])

    if findings:
        for idx, f in enumerate(findings[:8], 1):
            lines.append(f"  [{idx:02d}] {f['title']}: {f['metric']}")
            lines.append(f"       {f['description']}")
    else:
        lines.append("  * No automated findings generated.")

    lines.extend([
        "",
        "6. RECOMMENDED REMEDIATION & CONTAINMENT STRATEGY",
        "  1. Isolate internal host(s) exhibiting Command & Control (C2) beaconing.",
        "  2. Deploy perimeter drop rules for IP addresses executing active port scans.",
        "  3. Enforce MFA and rate-limiting on administrative SSH (22) and RDP (3389) ports.",
        "  4. Apply Web Application Firewall (WAF) virtual patching against SQLi/XSS probes.",
        "",
        "7. SYSTEM LIMITATIONS & ACADEMIC BOUNDARIES",
        "  * Operates on IP flow metadata (duration, packets, bytes, rate, 5-tuple).",
        "  * Does not decrypt TLS encrypted application layer payloads.",
        "  * Supervised models require periodic retraining to defend against concept drift.",
        "",
        "=" * 78,
        "END OF REPORT - NETGUARD AI SOC SYSTEM",
        "=" * 78,
    ])

    return "\n".join(lines)
