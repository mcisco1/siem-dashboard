import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "siem.db")

GENERATOR_INTERVAL = 3
LOG_BATCH_SIZE = 20

# token for API access — rotate this in production
API_TOKEN = os.environ.get("SIEM_API_TOKEN", "siem-ops-7f3a9c2e")

SEVERITY_LEVELS = {
    "critical": {"min_score": 9, "max_score": 10},
    "high":     {"min_score": 7, "max_score": 8},
    "medium":   {"min_score": 4, "max_score": 6},
    "low":      {"min_score": 1, "max_score": 3},
}

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 300
PORT_SCAN_THRESHOLD = 8
PORT_SCAN_WINDOW = 120
DDOS_THRESHOLD = 50
DDOS_WINDOW = 60

MITRE_MAPPING = {
    "brute_force":    {"tactic": "Credential Access", "technique": "T1110", "name": "Brute Force"},
    "port_scan":      {"tactic": "Discovery", "technique": "T1046", "name": "Network Service Scanning"},
    "ddos":           {"tactic": "Impact", "technique": "T1498", "name": "Network Denial of Service"},
    "malware_beacon": {"tactic": "Command and Control", "technique": "T1071", "name": "Application Layer Protocol"},
    "data_exfil":     {"tactic": "Exfiltration", "technique": "T1041", "name": "Exfiltration Over C2 Channel"},
    "privilege_esc":  {"tactic": "Privilege Escalation", "technique": "T1068", "name": "Exploitation for Privilege Escalation"},
}

THREAT_INTEL_IPS = [
    "185.220.101.34", "45.155.205.233", "89.248.167.131",
    "171.25.193.78", "62.102.148.68", "194.26.29.120",
    "23.129.64.210", "185.56.80.65", "91.219.236.222",
    "198.98.56.149",
]
