from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Event:
    timestamp: float
    source_ip: str
    dest_ip: str
    dest_port: int
    protocol: str
    event_type: str
    severity: str
    severity_score: int
    raw_log: str
    message: str
    username: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    flagged: int = 0

    def to_tuple(self):
        return (
            self.timestamp, self.source_ip, self.dest_ip, self.dest_port,
            self.protocol, self.event_type, self.severity, self.severity_score,
            self.raw_log, self.message, self.username, self.country, self.city,
            self.latitude, self.longitude, self.mitre_tactic, self.mitre_technique,
            self.flagged,
        )

    def to_dict(self):
        return asdict(self)


@dataclass
class Alert:
    timestamp: float
    alert_type: str
    severity: str
    severity_score: int
    source_ip: str
    description: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    event_count: int = 1

    def to_tuple(self):
        return (
            self.timestamp, self.alert_type, self.severity, self.severity_score,
            self.source_ip, self.description, self.mitre_tactic,
            self.mitre_technique, self.event_count,
        )

    def to_dict(self):
        return asdict(self)


@dataclass
class ThreatIntelHit:
    ip: str
    threat_type: str
    confidence: int = 85
    first_seen: float = 0.0
    last_seen: float = 0.0
    hit_count: int = 1
