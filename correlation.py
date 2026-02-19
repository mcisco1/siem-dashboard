import time
import database as db
from models import Alert
from config import (
    BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW,
    PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW,
    DDOS_THRESHOLD, DDOS_WINDOW,
    MITRE_MAPPING, THREAT_INTEL_IPS,
)


def correlate(events, db_path=None):
    """Run correlation rules against a batch of ingested events.
    Returns list of Alert objects that were triggered."""
    alerts = []
    checked_ips = set()

    for ev in events:
        src_ip = ev.source_ip if hasattr(ev, "source_ip") else ev[1]
        etype = ev.event_type if hasattr(ev, "event_type") else ev[5]
        flagged = ev.flagged if hasattr(ev, "flagged") else ev[17]

        if src_ip in checked_ips:
            continue

        if etype == "auth_failure":
            a = _check_brute_force(src_ip, db_path)
            if a:
                alerts.append(a)
                checked_ips.add(src_ip)

        if etype in ("port_scan", "firewall_drop", "firewall_reject"):
            a = _check_port_scan(src_ip, db_path)
            if a:
                alerts.append(a)
                checked_ips.add(src_ip)

        if flagged == 1:
            _handle_threat_intel(src_ip, etype, db_path)

    ddos = _check_ddos(db_path)
    if ddos:
        alerts.append(ddos)

    for alert in alerts:
        db.insert_alert(alert, db_path)

    return alerts


def _check_brute_force(src_ip, db_path=None):
    count = db.count_recent_by_ip(src_ip, "auth_failure", BRUTE_FORCE_WINDOW, db_path)
    if count >= BRUTE_FORCE_THRESHOLD:
        mitre = MITRE_MAPPING["brute_force"]
        return Alert(
            timestamp=time.time(), alert_type="brute_force", severity="high",
            severity_score=8, source_ip=src_ip,
            description=f"Brute force detected: {count} failed logins from {src_ip} in {BRUTE_FORCE_WINDOW}s",
            mitre_tactic=mitre["tactic"], mitre_technique=mitre["technique"],
            event_count=count,
        )
    return None


def _check_port_scan(src_ip, db_path=None):
    port_count = db.distinct_ports_by_ip(src_ip, PORT_SCAN_WINDOW, db_path)
    if port_count >= PORT_SCAN_THRESHOLD:
        mitre = MITRE_MAPPING["port_scan"]
        return Alert(
            timestamp=time.time(), alert_type="port_scan", severity="high",
            severity_score=7, source_ip=src_ip,
            description=f"Port scan detected: {src_ip} probed {port_count} distinct ports in {PORT_SCAN_WINDOW}s",
            mitre_tactic=mitre["tactic"], mitre_technique=mitre["technique"],
            event_count=port_count,
        )
    return None


def _check_ddos(db_path=None):
    count = db.count_recent_events(DDOS_WINDOW, db_path)
    if count >= DDOS_THRESHOLD:
        mitre = MITRE_MAPPING["ddos"]
        return Alert(
            timestamp=time.time(), alert_type="ddos_suspected", severity="critical",
            severity_score=10, source_ip="multiple",
            description=f"Possible DDoS: {count} events in {DDOS_WINDOW}s exceeds threshold",
            mitre_tactic=mitre["tactic"], mitre_technique=mitre["technique"],
            event_count=count,
        )
    return None


def _handle_threat_intel(src_ip, event_type, db_path=None):
    db.log_threat_intel_hit(src_ip, event_type, db_path)
