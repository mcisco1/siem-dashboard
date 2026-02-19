import random
import time
from config import THREAT_INTEL_IPS, SEVERITY_LEVELS
from models import Event

GEO_PROFILES = [
    {"country": "United States", "city": "New York", "lat": 40.7128, "lng": -74.0060},
    {"country": "United States", "city": "Los Angeles", "lat": 34.0522, "lng": -118.2437},
    {"country": "United States", "city": "Chicago", "lat": 41.8781, "lng": -87.6298},
    {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lng": 37.6173},
    {"country": "Russia", "city": "Saint Petersburg", "lat": 59.9343, "lng": 30.3351},
    {"country": "China", "city": "Beijing", "lat": 39.9042, "lng": 116.4074},
    {"country": "China", "city": "Shanghai", "lat": 31.2304, "lng": 121.4737},
    {"country": "Germany", "city": "Berlin", "lat": 52.5200, "lng": 13.4050},
    {"country": "Brazil", "city": "São Paulo", "lat": -23.5505, "lng": -46.6333},
    {"country": "Nigeria", "city": "Lagos", "lat": 6.5244, "lng": 3.3792},
    {"country": "Iran", "city": "Tehran", "lat": 35.6892, "lng": 51.3890},
    {"country": "North Korea", "city": "Pyongyang", "lat": 39.0392, "lng": 125.7625},
    {"country": "India", "city": "Mumbai", "lat": 19.0760, "lng": 72.8777},
    {"country": "Romania", "city": "Bucharest", "lat": 44.4268, "lng": 26.1025},
    {"country": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lng": 4.9041},
    {"country": "United Kingdom", "city": "London", "lat": 51.5074, "lng": -0.1278},
    {"country": "South Korea", "city": "Seoul", "lat": 37.5665, "lng": 126.9780},
    {"country": "Ukraine", "city": "Kyiv", "lat": 50.4501, "lng": 30.5234},
]

INTERNAL_SUBNETS = ["10.0.1", "10.0.2", "10.0.3", "192.168.1", "192.168.10"]
EXTERNAL_RANGES = ["185.220", "45.155", "89.248", "103.42", "77.91", "62.102", "194.26", "212.70", "91.219"]
USERNAMES = ["admin", "root", "jsmith", "agarcia", "mwilliams", "test", "backup",
             "ftpuser", "oracle", "postgres", "deploy", "sysadmin", "guest",
             "service_acct", "www-data", "nobody", "operator"]
SERVICES = ["sshd", "httpd", "nginx", "mysqld", "postfix", "vsftpd", "named", "smbd", "crond", "systemd"]
COMMON_PORTS = [22, 80, 443, 3306, 8080, 21, 25, 53, 445, 3389, 8443, 5432, 6379, 27017, 9200]

EVENT_WEIGHTS = {
    "auth_success": 20, "auth_failure": 15,
    "firewall_allow": 18, "firewall_drop": 12, "firewall_reject": 5,
    "port_scan": 4, "connection_established": 15, "connection_timeout": 6,
    "malware_signature": 2, "privilege_escalation": 1, "data_exfiltration": 1,
    "dns_query": 12, "service_start": 3, "service_stop": 2, "config_change": 2,
}

SEVERITY_MAP = {
    "auth_success": "low", "auth_failure": "medium",
    "firewall_allow": "low", "firewall_drop": "medium", "firewall_reject": "medium",
    "port_scan": "high", "connection_established": "low", "connection_timeout": "low",
    "malware_signature": "critical", "privilege_escalation": "critical",
    "data_exfiltration": "critical", "dns_query": "low",
    "service_start": "low", "service_stop": "medium", "config_change": "high",
}

MITRE_MAP = {
    "auth_failure": ("Credential Access", "T1110"),
    "port_scan": ("Discovery", "T1046"),
    "malware_signature": ("Command and Control", "T1071"),
    "data_exfiltration": ("Exfiltration", "T1041"),
    "privilege_escalation": ("Privilege Escalation", "T1068"),
}


def _rand_internal_ip():
    return f"{random.choice(INTERNAL_SUBNETS)}.{random.randint(2, 254)}"


def _rand_external_ip():
    if random.random() < 0.15:
        return random.choice(THREAT_INTEL_IPS)
    return f"{random.choice(EXTERNAL_RANGES)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def _geo_for_ip(ip):
    if any(ip.startswith(s) for s in INTERNAL_SUBNETS):
        return {"country": "United States", "city": "Internal Network", "lat": 40.7128, "lng": -74.0060}
    return random.Random(ip).choice(GEO_PROFILES)


def _pick_event_type():
    types = list(EVENT_WEIGHTS.keys())
    weights = list(EVENT_WEIGHTS.values())
    return random.choices(types, weights=weights, k=1)[0]


def _build_raw_log(ts, etype, src, dst, port, proto, user, svc):
    t = time.strftime("%b %d %H:%M:%S", time.localtime(ts))
    h = "siem-sensor-01"
    pid = random.randint(1000, 9999)
    ephemeral = random.randint(30000, 65000)

    if etype == "auth_failure":
        return f"{t} {h} {svc}[{pid}]: Failed password for {user} from {src} port {ephemeral} {proto}"
    if etype == "auth_success":
        return f"{t} {h} {svc}[{pid}]: Accepted publickey for {user} from {src} port {ephemeral} {proto}"
    if etype.startswith("firewall"):
        action = etype.split("_")[1].upper()
        return f"{t} {h} kernel: iptables {action} IN=eth0 SRC={src} DST={dst} PROTO={proto} DPT={port}"
    if etype == "port_scan":
        return f"{t} {h} snort[{pid}]: [1:1000001:1] PORT SCAN detected from {src} targeting {dst} ports {port}-{port+100}"
    if etype == "malware_signature":
        sigs = ["Win.Trojan.Agent-123", "Backdoor.Linux.Mirai", "Exploit.CVE-2024-3094", "Ransomware.WannaCry.variant"]
        return f"{t} {h} clamav[{pid}]: ALERT - {random.choice(sigs)} detected in traffic from {src} to {dst}:{port}"
    if etype == "privilege_escalation":
        return f"{t} {h} sudo: {user} : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash (UNAUTHORIZED)"
    if etype == "data_exfiltration":
        mb = random.randint(50, 500)
        return f"{t} {h} dlp[{pid}]: Large outbound transfer {mb}MB from {src} to {dst}:{port} flagged"
    if etype == "dns_query":
        domains = ["google.com", "evil-c2-server.xyz", "microsoft.com", "update.malware.ru", "cdn.normal-site.com"]
        return f"{t} {h} named[{pid}]: query: {random.choice(domains)} IN A from {src}"
    if etype == "config_change":
        files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/iptables/rules.v4"]
        return f"{t} {h} auditd[{pid}]: MODIFY {random.choice(files)} by uid={random.randint(0, 1000)}"
    if etype == "service_start":
        return f"{t} {h} systemd[1]: Started {svc}.service"
    if etype == "service_stop":
        return f"{t} {h} systemd[1]: Stopped {svc}.service"
    return f"{t} {h} {svc}[{pid}]: {proto} connection {src}:{ephemeral} -> {dst}:{port}"


def _build_message(etype, src, dst, port, user):
    msgs = {
        "auth_success": f"Successful login by {user} from {src}",
        "auth_failure": f"Failed login attempt for {user} from {src}",
        "firewall_allow": f"Allowed {src} -> {dst}:{port}",
        "firewall_drop": f"Dropped packet from {src} -> {dst}:{port}",
        "firewall_reject": f"Rejected connection from {src} -> {dst}:{port}",
        "port_scan": f"Port scan detected from {src} targeting {dst}",
        "connection_established": f"Connection {src} -> {dst}:{port} established",
        "connection_timeout": f"Connection timeout {src} -> {dst}:{port}",
        "malware_signature": f"Malware signature matched in traffic from {src}",
        "privilege_escalation": f"Unauthorized privilege escalation by {user} on {dst}",
        "data_exfiltration": f"Suspicious large data transfer {src} -> {dst}:{port}",
        "dns_query": f"DNS query from {src}",
        "service_start": f"Service started on {dst}",
        "service_stop": f"Service stopped on {dst}",
        "config_change": f"Critical config file modified on {dst}",
    }
    return msgs.get(etype, f"Event from {src}")


def generate_batch(count):
    now = time.time()
    events = []
    for _ in range(count):
        ts = now - random.uniform(0, 2)
        etype = _pick_event_type()

        is_external = etype in ("auth_failure", "port_scan", "malware_signature",
                                "data_exfiltration", "firewall_drop", "firewall_reject")
        src = _rand_external_ip() if is_external else _rand_internal_ip()
        dst = _rand_internal_ip()
        port = random.choice(COMMON_PORTS)
        proto = "UDP" if etype == "dns_query" else random.choice(["TCP", "UDP"])
        user = random.choice(USERNAMES) if ("auth" in etype or etype == "privilege_escalation") else None
        svc = random.choice(SERVICES)

        severity = SEVERITY_MAP.get(etype, "medium")
        bounds = SEVERITY_LEVELS[severity]
        score = random.randint(bounds["min_score"], bounds["max_score"])
        geo = _geo_for_ip(src)
        tactic, tech = MITRE_MAP.get(etype, (None, None))
        flagged = 1 if src in THREAT_INTEL_IPS else 0

        raw = _build_raw_log(ts, etype, src, dst, port, proto, user, svc)
        msg = _build_message(etype, src, dst, port, user)

        events.append(Event(
            timestamp=ts, source_ip=src, dest_ip=dst, dest_port=port,
            protocol=proto, event_type=etype, severity=severity,
            severity_score=score, raw_log=raw, message=msg, username=user,
            country=geo["country"], city=geo["city"],
            latitude=geo["lat"], longitude=geo["lng"],
            mitre_tactic=tactic, mitre_technique=tech, flagged=flagged,
        ))
    return events
