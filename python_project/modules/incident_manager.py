"""
Incident Investigation Workspace Module for NETGUARD AI
Assists Junior SOC Analysts with threat investigation, evidence correlation, and playbooks.
"""

PLAYBOOK_RECOMMENDATIONS = {
    "DoS / DDoS": [
        "1. Verify target host health and system resource utilization (CPU, memory, connection tables).",
        "2. Apply upstream SYN cookies and connection rate limiting on edge firewalls/WAF.",
        "3. Coordinate with upstream ISP/Cloud provider to null-route attacking IP prefixes if pipe is saturated.",
        "4. Confirm return to normal latency and document attack duration in incident ticket."
    ],
    "Brute Force": [
        "1. Inspect host authentication logs (e.g. /var/log/auth.log or Event ID 4625).",
        "2. Verify whether any attempted logins were successful from the suspect IP address.",
        "3. Reset credentials for targeted user accounts and enforce multi-factor authentication (MFA).",
        "4. Blacklist the source IP on border security perimeter and verify failed attempt count drop."
    ],
    "Port Scan": [
        "1. Confirm if source IP belongs to internal vulnerability assessment teams or pen testers.",
        "2. Review destination ports to identify if any unauthorized listening services responded.",
        "3. Audit host firewall rules to verify unnecessary ports remain closed or filtered.",
        "4. Ingest attacking IP into perimeter blocklist if scan was external and uncoordinated."
    ],
    "Web Attack": [
        "1. Inspect web application server access logs and WAF telemetry for payload injection signatures.",
        "2. Verify whether backend database executed anomalous queries or leaked internal stack traces.",
        "3. Review application source code around the vulnerable URI parameter for input validation.",
        "4. Deploy virtual patch via Web Application Firewall (WAF) rule."
    ],
    "Botnet / C2": [
        "1. Immediately isolate the internal endpoint from the local VLAN to prevent lateral infection.",
        "2. Capture volatile RAM memory dump and disk image for digital forensics and reverse engineering.",
        "3. Block the destination C2 domain and IP across enterprise DNS resolvers and perimeter firewalls.",
        "4. Run deep anti-malware and EDR remediation on the infected workstation."
    ],
}


def get_incident_playbook(category: str) -> list[str]:
    """
    Returns incident investigation playbook steps for a specific threat category.
    """
    return PLAYBOOK_RECOMMENDATIONS.get(category, [
        "1. Review full packet capture (PCAP) and protocol headers if available.",
        "2. Correlate timestamp with endpoint syslog and proxy gateway logs.",
        "3. Check external IP address reputation in threat intelligence feeds.",
        "4. Record all findings and mitigation steps in the investigation notes."
    ])
