"""
Simulates a realistic multi-stage intrusion:
  1. Reconnaissance — attacker scans ports on a target server
  2. Brute Force — rapid SSH login attempts against common accounts
  3. Initial Access — attacker gets in after credential guessing
  4. Privilege Escalation — sudo abuse to gain root
  5. Persistence — config file modifications (backdoor sshd, add user)
  6. Exfiltration — large data transfer out to attacker-controlled IP

This runs on a timer alongside normal traffic so the attack builds
gradually and shows up across multiple dashboard panels.
"""

import time
import random
from models import Event
from config import SEVERITY_LEVELS

ATTACKER_IP = "185.220.101.34"
ATTACKER_GEO = {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lng": 37.6173}
TARGET_IP = "10.0.1.50"
TARGET_USER = "admin"
EXFIL_PORTS = [443, 8443]


class AttackScenario:
    def __init__(self):
        self.phase = 0
        self.tick = 0
        self.started_at = time.time()
        # phase boundaries (in ticks, each tick = one generator cycle)
        self.phases = {
            0: (0, 10),     # recon: ticks 0-10
            1: (10, 25),    # brute force: ticks 10-25
            2: (25, 28),    # initial access: ticks 25-28
            3: (28, 32),    # priv esc: ticks 28-32
            4: (32, 38),    # persistence: ticks 32-38
            5: (38, 45),    # exfil: ticks 38-45
        }
        self.completed = False

    def advance(self):
        """Call once per generator cycle. Returns list of Event objects for the current phase."""
        if self.completed:
            return []

        events = []
        now = time.time()

        for phase_id, (start, end) in self.phases.items():
            if start <= self.tick < end:
                self.phase = phase_id
                break
        else:
            self.completed = True
            return []

        if self.phase == 0:
            events = self._recon_phase(now)
        elif self.phase == 1:
            events = self._brute_force_phase(now)
        elif self.phase == 2:
            events = self._initial_access_phase(now)
        elif self.phase == 3:
            events = self._priv_esc_phase(now)
        elif self.phase == 4:
            events = self._persistence_phase(now)
        elif self.phase == 5:
            events = self._exfil_phase(now)

        self.tick += 1
        return events

    def _recon_phase(self, now):
        events = []
        scan_ports = random.sample(range(1, 1024), random.randint(3, 8))
        for port in scan_ports:
            events.append(self._make_event(
                now, "port_scan", "high", port, "TCP",
                f"Port scan from {ATTACKER_IP} -> {TARGET_IP}:{port}",
                f"Feb 19 {time.strftime('%H:%M:%S')} siem-sensor-01 snort[{random.randint(1000,9999)}]: "
                f"[1:1000001:1] PORT SCAN detected from {ATTACKER_IP} targeting {TARGET_IP} ports {port}-{port+50}",
                mitre_tactic="Discovery", mitre_technique="T1046",
            ))
        return events

    def _brute_force_phase(self, now):
        events = []
        usernames = ["root", "admin", "administrator", "deploy", "ubuntu", "test"]
        for user in random.sample(usernames, random.randint(2, 4)):
            events.append(self._make_event(
                now, "auth_failure", "medium", 22, "TCP",
                f"Failed login attempt for {user} from {ATTACKER_IP}",
                f"Feb 19 {time.strftime('%H:%M:%S')} siem-sensor-01 sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {user} from {ATTACKER_IP} port {random.randint(40000,60000)} TCP",
                username=user, mitre_tactic="Credential Access", mitre_technique="T1110",
            ))
        return events

    def _initial_access_phase(self, now):
        return [self._make_event(
            now, "auth_success", "high", 22, "TCP",
            f"Successful login by {TARGET_USER} from {ATTACKER_IP}",
            f"Feb 19 {time.strftime('%H:%M:%S')} siem-sensor-01 sshd[{random.randint(1000,9999)}]: "
            f"Accepted password for {TARGET_USER} from {ATTACKER_IP} port {random.randint(40000,60000)} TCP",
            username=TARGET_USER, severity_override="high", score_override=8,
        )]

    def _priv_esc_phase(self, now):
        return [self._make_event(
            now, "privilege_escalation", "critical", 22, "TCP",
            f"Unauthorized privilege escalation by {TARGET_USER} on {TARGET_IP}",
            f"Feb 19 {time.strftime('%H:%M:%S')} siem-sensor-01 sudo: {TARGET_USER} : "
            f"TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash (UNAUTHORIZED)",
            username=TARGET_USER, mitre_tactic="Privilege Escalation", mitre_technique="T1068",
        )]

    def _persistence_phase(self, now):
        events = []
        targets = [
            ("/etc/ssh/sshd_config", "Backdoor SSH config — permitrootlogin set to yes"),
            ("/etc/passwd", "New user account created — backdoor_user uid=0"),
            ("/etc/crontab", "Cron job added — reverse shell scheduled every 5 min"),
        ]
        for path, desc in targets:
            events.append(self._make_event(
                now, "config_change", "critical", 22, "TCP",
                f"Critical config file modified on {TARGET_IP}: {path}",
                f"Feb 19 {time.strftime('%H:%M:%S')} siem-sensor-01 auditd[{random.randint(1000,9999)}]: "
                f"MODIFY {path} by uid=0 — {desc}",
                username="root", mitre_tactic="Persistence", mitre_technique="T1098",
                score_override=10, severity_override="critical",
            ))
        return events

    def _exfil_phase(self, now):
        events = []
        for _ in range(random.randint(2, 4)):
            mb = random.randint(100, 800)
            port = random.choice(EXFIL_PORTS)
            events.append(self._make_event(
                now, "data_exfiltration", "critical", port, "TCP",
                f"Suspicious large data transfer {TARGET_IP} -> {ATTACKER_IP}:{port} ({mb}MB)",
                f"Feb 19 {time.strftime('%H:%M:%S')} siem-sensor-01 dlp[{random.randint(1000,9999)}]: "
                f"Large outbound transfer {mb}MB from {TARGET_IP} to {ATTACKER_IP}:{port} flagged",
                mitre_tactic="Exfiltration", mitre_technique="T1041",
                # exfil goes from target outward, so swap src/dst
                src_override=TARGET_IP, dst_override=ATTACKER_IP,
            ))
        return events

    def _make_event(self, now, etype, severity, port, proto, message, raw_log,
                    username=None, mitre_tactic=None, mitre_technique=None,
                    severity_override=None, score_override=None,
                    src_override=None, dst_override=None):
        sev = severity_override or severity
        bounds = SEVERITY_LEVELS[sev]
        score = score_override or random.randint(bounds["min_score"], bounds["max_score"])

        return Event(
            timestamp=now - random.uniform(0, 1),
            source_ip=src_override or ATTACKER_IP,
            dest_ip=dst_override or TARGET_IP,
            dest_port=port,
            protocol=proto,
            event_type=etype,
            severity=sev,
            severity_score=score,
            raw_log=raw_log,
            message=message,
            username=username,
            country=ATTACKER_GEO["country"],
            city=ATTACKER_GEO["city"],
            latitude=ATTACKER_GEO["lat"],
            longitude=ATTACKER_GEO["lng"],
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            flagged=1,
        )
