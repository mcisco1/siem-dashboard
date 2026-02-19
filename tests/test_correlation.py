import os
import sys
import time
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database as db
from models import Event, Alert
from log_generator import generate_batch
from correlation import correlate, _check_brute_force, _check_port_scan, _check_ddos
import config


class TestModels(unittest.TestCase):
    def test_event_to_tuple_length(self):
        ev = Event(
            timestamp=time.time(), source_ip="1.2.3.4", dest_ip="10.0.1.5",
            dest_port=22, protocol="TCP", event_type="auth_failure",
            severity="medium", severity_score=5, raw_log="test", message="test msg",
        )
        self.assertEqual(len(ev.to_tuple()), 18)

    def test_event_to_dict(self):
        ev = Event(
            timestamp=1000.0, source_ip="5.6.7.8", dest_ip="10.0.1.1",
            dest_port=80, protocol="TCP", event_type="firewall_drop",
            severity="medium", severity_score=4, raw_log="raw", message="msg",
            country="Russia", city="Moscow",
        )
        d = ev.to_dict()
        self.assertEqual(d["source_ip"], "5.6.7.8")
        self.assertEqual(d["country"], "Russia")

    def test_alert_to_tuple_length(self):
        a = Alert(
            timestamp=time.time(), alert_type="brute_force", severity="high",
            severity_score=8, source_ip="1.1.1.1", description="test alert",
        )
        self.assertEqual(len(a.to_tuple()), 9)

    def test_event_defaults(self):
        ev = Event(
            timestamp=0, source_ip="x", dest_ip="y", dest_port=0,
            protocol="TCP", event_type="test", severity="low",
            severity_score=1, raw_log="", message="",
        )
        self.assertIsNone(ev.username)
        self.assertIsNone(ev.mitre_tactic)
        self.assertEqual(ev.flagged, 0)


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        db.init_db(self.db_path)

    def tearDown(self):
        os.unlink(self.db_path)

    def _make_event(self, **overrides):
        defaults = dict(
            timestamp=time.time(), source_ip="10.0.1.5", dest_ip="10.0.1.1",
            dest_port=22, protocol="TCP", event_type="auth_failure",
            severity="medium", severity_score=5, raw_log="test log",
            message="test", username="admin", country="US", city="NY",
            latitude=40.7, longitude=-74.0, mitre_tactic=None,
            mitre_technique=None, flagged=0,
        )
        defaults.update(overrides)
        return Event(**defaults)

    def test_insert_and_query(self):
        events = [self._make_event() for _ in range(5)]
        db.insert_events(events, self.db_path)
        result = db.recent_events(10, db_path=self.db_path)
        self.assertEqual(len(result), 5)

    def test_severity_counts(self):
        events = [
            self._make_event(severity="critical", severity_score=10),
            self._make_event(severity="critical", severity_score=9),
            self._make_event(severity="low", severity_score=1),
        ]
        db.insert_events(events, self.db_path)
        counts = db.severity_counts(since=time.time() - 60, db_path=self.db_path)
        self.assertEqual(counts.get("critical"), 2)
        self.assertEqual(counts.get("low"), 1)

    def test_filter_by_severity(self):
        events = [
            self._make_event(severity="critical"),
            self._make_event(severity="low"),
        ]
        db.insert_events(events, self.db_path)
        result = db.recent_events(10, severity="critical", db_path=self.db_path)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "critical")

    def test_filter_by_source_ip(self):
        events = [
            self._make_event(source_ip="1.1.1.1"),
            self._make_event(source_ip="2.2.2.2"),
            self._make_event(source_ip="1.1.1.1"),
        ]
        db.insert_events(events, self.db_path)
        result = db.recent_events(10, source_ip="1.1.1.1", db_path=self.db_path)
        self.assertEqual(len(result), 2)

    def test_alert_acknowledge(self):
        alert = Alert(
            timestamp=time.time(), alert_type="test", severity="high",
            severity_score=7, source_ip="1.1.1.1", description="test",
        )
        db.insert_alert(alert, self.db_path)
        alerts = db.recent_alerts(db_path=self.db_path)
        self.assertEqual(alerts[0]["acknowledged"], 0)
        db.acknowledge_alert(alerts[0]["id"], self.db_path)
        alerts = db.recent_alerts(db_path=self.db_path)
        self.assertEqual(alerts[0]["acknowledged"], 1)

    def test_analyst_notes(self):
        alert = Alert(
            timestamp=time.time(), alert_type="test", severity="high",
            severity_score=7, source_ip="1.1.1.1", description="desc",
        )
        db.insert_alert(alert, self.db_path)
        alerts = db.recent_alerts(db_path=self.db_path)
        db.add_analyst_note(alerts[0]["id"], "investigated — false positive", self.db_path)
        alerts = db.recent_alerts(db_path=self.db_path)
        self.assertIn("false positive", alerts[0]["analyst_notes"])

    def test_threat_intel_hit(self):
        db.log_threat_intel_hit("5.5.5.5", "port_scan", self.db_path)
        db.log_threat_intel_hit("5.5.5.5", "port_scan", self.db_path)
        hits = db.threat_intel_hits(self.db_path)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["hit_count"], 2)

    def test_time_range_filter(self):
        old = self._make_event(timestamp=time.time() - 7200)
        recent = self._make_event(timestamp=time.time() - 30)
        db.insert_events([old, recent], self.db_path)
        result = db.recent_events(10, since=time.time() - 60, db_path=self.db_path)
        self.assertEqual(len(result), 1)


class TestCorrelation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        db.init_db(self.db_path)

    def tearDown(self):
        os.unlink(self.db_path)

    def _make_event(self, **overrides):
        defaults = dict(
            timestamp=time.time(), source_ip="185.220.101.34", dest_ip="10.0.1.1",
            dest_port=22, protocol="TCP", event_type="auth_failure",
            severity="medium", severity_score=5, raw_log="test",
            message="test", username="root", country="Russia", city="Moscow",
            latitude=55.7, longitude=37.6, mitre_tactic="Credential Access",
            mitre_technique="T1110", flagged=1,
        )
        defaults.update(overrides)
        return Event(**defaults)

    def test_brute_force_triggers(self):
        attacker = "99.99.99.99"
        events = [
            self._make_event(source_ip=attacker, flagged=0)
            for _ in range(config.BRUTE_FORCE_THRESHOLD + 2)
        ]
        db.insert_events(events, self.db_path)
        alert = _check_brute_force(attacker, self.db_path)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "brute_force")
        self.assertEqual(alert.severity, "high")
        self.assertIn(attacker, alert.description)

    def test_brute_force_below_threshold(self):
        attacker = "88.88.88.88"
        events = [
            self._make_event(source_ip=attacker, flagged=0)
            for _ in range(config.BRUTE_FORCE_THRESHOLD - 2)
        ]
        db.insert_events(events, self.db_path)
        alert = _check_brute_force(attacker, self.db_path)
        self.assertIsNone(alert)

    def test_port_scan_triggers(self):
        scanner = "77.77.77.77"
        events = []
        for port in range(1, config.PORT_SCAN_THRESHOLD + 3):
            events.append(self._make_event(
                source_ip=scanner, dest_port=port,
                event_type="firewall_drop", flagged=0,
            ))
        db.insert_events(events, self.db_path)
        alert = _check_port_scan(scanner, self.db_path)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "port_scan")

    def test_port_scan_below_threshold(self):
        scanner = "66.66.66.66"
        events = [
            self._make_event(
                source_ip=scanner, dest_port=22,
                event_type="firewall_drop", flagged=0,
            )
            for _ in range(3)
        ]
        db.insert_events(events, self.db_path)
        alert = _check_port_scan(scanner, self.db_path)
        self.assertIsNone(alert)

    def test_ddos_triggers(self):
        events = [
            self._make_event(
                source_ip=f"10.0.1.{i % 254 + 1}",
                event_type="connection_established",
                severity="low", severity_score=1, flagged=0,
            )
            for i in range(config.DDOS_THRESHOLD + 5)
        ]
        db.insert_events(events, self.db_path)
        alert = _check_ddos(self.db_path)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "ddos_suspected")
        self.assertEqual(alert.severity, "critical")

    def test_ddos_below_threshold(self):
        events = [
            self._make_event(
                source_ip="10.0.1.5", event_type="connection_established",
                severity="low", severity_score=1, flagged=0,
            )
            for _ in range(3)
        ]
        db.insert_events(events, self.db_path)
        alert = _check_ddos(self.db_path)
        self.assertIsNone(alert)

    def test_correlate_full_pipeline(self):
        attacker = "44.44.44.44"
        events = [
            self._make_event(source_ip=attacker, flagged=0)
            for _ in range(config.BRUTE_FORCE_THRESHOLD + 3)
        ]
        db.insert_events(events, self.db_path)
        alerts = correlate(events, self.db_path)
        brute_alerts = [a for a in alerts if a.alert_type == "brute_force"]
        self.assertTrue(len(brute_alerts) >= 1)

    def test_correlate_deduplicates_ips(self):
        attacker = "33.33.33.33"
        events = [
            self._make_event(source_ip=attacker, flagged=0)
            for _ in range(config.BRUTE_FORCE_THRESHOLD + 5)
        ]
        db.insert_events(events, self.db_path)
        alerts = correlate(events, self.db_path)
        brute_alerts = [a for a in alerts if a.alert_type == "brute_force" and a.source_ip == attacker]
        self.assertEqual(len(brute_alerts), 1)

    def test_threat_intel_flagging(self):
        ti_ip = config.THREAT_INTEL_IPS[0]
        events = [self._make_event(source_ip=ti_ip, flagged=1)]
        db.insert_events(events, self.db_path)
        correlate(events, self.db_path)
        hits = db.threat_intel_hits(self.db_path)
        matched = [h for h in hits if h["ip"] == ti_ip]
        self.assertTrue(len(matched) >= 1)

    def test_alert_has_mitre_mapping(self):
        attacker = "22.22.22.22"
        events = [
            self._make_event(source_ip=attacker, flagged=0)
            for _ in range(config.BRUTE_FORCE_THRESHOLD + 1)
        ]
        db.insert_events(events, self.db_path)
        alert = _check_brute_force(attacker, self.db_path)
        self.assertEqual(alert.mitre_tactic, "Credential Access")
        self.assertEqual(alert.mitre_technique, "T1110")


class TestLogGenerator(unittest.TestCase):
    def test_batch_size(self):
        batch = generate_batch(15)
        self.assertEqual(len(batch), 15)

    def test_event_is_dataclass(self):
        batch = generate_batch(5)
        for ev in batch:
            self.assertIsInstance(ev, Event)
            self.assertTrue(hasattr(ev, "to_tuple"))
            self.assertTrue(hasattr(ev, "source_ip"))

    def test_severity_valid(self):
        batch = generate_batch(50)
        valid = {"critical", "high", "medium", "low"}
        for ev in batch:
            self.assertIn(ev.severity, valid)

    def test_score_within_bounds(self):
        batch = generate_batch(100)
        for ev in batch:
            bounds = config.SEVERITY_LEVELS[ev.severity]
            self.assertGreaterEqual(ev.severity_score, bounds["min_score"])
            self.assertLessEqual(ev.severity_score, bounds["max_score"])

    def test_raw_log_not_empty(self):
        batch = generate_batch(20)
        for ev in batch:
            self.assertTrue(len(ev.raw_log) > 0)


if __name__ == "__main__":
    unittest.main()
