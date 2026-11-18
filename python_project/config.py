"""
NETGUARD AI Configuration File
Intelligent Network Threat Detection & Security Monitoring
"""

import os

# Application Metadata
APP_NAME = "NETGUARD AI"
TAGLINE = "Intelligent Network Threat Detection & Security Monitoring"
VERSION = "1.0.0"
ACADEMIC_YEAR = "2026"
PROJECT_TYPE = "B.Sc. Computer Science Cybersecurity Capstone"

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "incidents.db")
SAMPLE_DATA_PATH = os.path.join(DATA_DIR, "sample_network_traffic.csv")

# Ensure required directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(DB_DIR, exist_ok=True)

# Machine Learning Parameters
RANDOM_STATE = 42
TRAIN_TEST_SPLIT_RATIO = 0.75
MAX_DECISION_TREE_DEPTH = 6
RANDOM_FOREST_ESTIMATORS = 50

# Standard Column Mapping
REQUIRED_COLUMNS = [
    "Timestamp",
    "Source_IP",
    "Destination_IP",
    "Source_Port",
    "Destination_Port",
    "Protocol",
    "Flow_Duration",
    "Packet_Count",
    "Byte_Count",
    "Flow_Rate",
]

# Sensitive ports for threat prioritization
SENSITIVE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit C2",
    8080: "HTTP-Proxy",
}
