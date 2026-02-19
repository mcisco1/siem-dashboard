import sqlite3
import time
from config import DATABASE_PATH


def get_conn(db_path=None):
    path = db_path or DATABASE_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db(db_path=None):
    conn = get_conn(db_path)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            source_ip TEXT,
            dest_ip TEXT,
            dest_port INTEGER,
            protocol TEXT,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            severity_score INTEGER DEFAULT 0,
            raw_log TEXT,
            message TEXT,
            username TEXT,
            country TEXT,
            city TEXT,
            latitude REAL,
            longitude REAL,
            mitre_tactic TEXT,
            mitre_technique TEXT,
            flagged INTEGER DEFAULT 0
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            severity_score INTEGER DEFAULT 0,
            source_ip TEXT,
            description TEXT,
            mitre_tactic TEXT,
            mitre_technique TEXT,
            event_count INTEGER DEFAULT 1,
            acknowledged INTEGER DEFAULT 0,
            analyst_notes TEXT DEFAULT ''
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel (
            ip TEXT PRIMARY KEY,
            threat_type TEXT,
            confidence INTEGER,
            first_seen REAL,
            last_seen REAL,
            hit_count INTEGER DEFAULT 0
        )
    """)

    c.execute("CREATE INDEX IF NOT EXISTS idx_ev_ts ON events(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ev_src ON events(source_ip)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ev_sev ON events(severity)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ev_type ON events(event_type)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_al_ts ON alerts(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_al_ack ON alerts(acknowledged)")

    conn.commit()
    conn.close()


def insert_events(events, db_path=None):
    """Takes a list of Event dataclass instances or raw tuples."""
    conn = get_conn(db_path)
    tuples = []
    for ev in events:
        if hasattr(ev, "to_tuple"):
            tuples.append(ev.to_tuple())
        else:
            tuples.append(ev)
    conn.executemany("""
        INSERT INTO events (timestamp, source_ip, dest_ip, dest_port, protocol,
            event_type, severity, severity_score, raw_log, message, username,
            country, city, latitude, longitude, mitre_tactic, mitre_technique, flagged)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, tuples)
    conn.commit()
    conn.close()


def insert_alert(alert, db_path=None):
    """Takes an Alert dataclass or positional args tuple."""
    conn = get_conn(db_path)
    if hasattr(alert, "to_tuple"):
        t = alert.to_tuple()
    else:
        t = alert
    conn.execute("""
        INSERT INTO alerts (timestamp, alert_type, severity, severity_score,
            source_ip, description, mitre_tactic, mitre_technique, event_count)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, t)
    conn.commit()
    conn.close()


def log_threat_intel_hit(ip, threat_type, db_path=None):
    conn = get_conn(db_path)
    now = time.time()
    existing = conn.execute("SELECT * FROM threat_intel WHERE ip=?", (ip,)).fetchone()
    if existing:
        conn.execute("UPDATE threat_intel SET last_seen=?, hit_count=hit_count+1 WHERE ip=?", (now, ip))
    else:
        conn.execute("""
            INSERT INTO threat_intel (ip, threat_type, confidence, first_seen, last_seen, hit_count)
            VALUES (?,?,85,?,?,1)
        """, (ip, threat_type, now, now))
    conn.commit()
    conn.close()


# ---- queries ----

def recent_events(limit=200, since=None, until=None, severity=None, event_type=None, source_ip=None, db_path=None):
    conn = get_conn(db_path)
    query = "SELECT * FROM events WHERE 1=1"
    params = []
    if since:
        query += " AND timestamp >= ?"
        params.append(since)
    if until:
        query += " AND timestamp <= ?"
        params.append(until)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)
    if source_ip:
        query += " AND source_ip = ?"
        params.append(source_ip)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def recent_alerts(limit=50, db_path=None):
    conn = get_conn(db_path)
    rows = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def severity_counts(since=None, until=None, db_path=None):
    conn = get_conn(db_path)
    since = since or (time.time() - 3600)
    query = "SELECT severity, COUNT(*) as cnt FROM events WHERE timestamp >= ?"
    params = [since]
    if until:
        query += " AND timestamp <= ?"
        params.append(until)
    query += " GROUP BY severity"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return {r["severity"]: r["cnt"] for r in rows}


def event_type_counts(since=None, until=None, db_path=None):
    conn = get_conn(db_path)
    since = since or (time.time() - 3600)
    query = "SELECT event_type, COUNT(*) as cnt FROM events WHERE timestamp >= ?"
    params = [since]
    if until:
        query += " AND timestamp <= ?"
        params.append(until)
    query += " GROUP BY event_type ORDER BY cnt DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return {r["event_type"]: r["cnt"] for r in rows}


def top_sources(limit=10, since=None, until=None, db_path=None):
    conn = get_conn(db_path)
    since = since or (time.time() - 3600)
    query = """
        SELECT source_ip, country, city, COUNT(*) as total,
            SUM(CASE WHEN severity IN ('critical','high') THEN 1 ELSE 0 END) as high_sev
        FROM events WHERE timestamp >= ?
    """
    params = [since]
    if until:
        query += " AND timestamp <= ?"
        params.append(until)
    query += " GROUP BY source_ip ORDER BY total DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def geo_breakdown(since=None, until=None, db_path=None):
    conn = get_conn(db_path)
    since = since or (time.time() - 3600)
    query = """
        SELECT country, city, COUNT(*) as cnt,
            AVG(latitude) as lat, AVG(longitude) as lng,
            SUM(CASE WHEN severity IN ('critical','high') THEN 1 ELSE 0 END) as threats
        FROM events WHERE timestamp >= ? AND latitude IS NOT NULL
    """
    params = [since]
    if until:
        query += " AND timestamp <= ?"
        params.append(until)
    query += " GROUP BY country, city ORDER BY cnt DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def timeline_buckets(since=None, until=None, bucket_sec=60, db_path=None):
    conn = get_conn(db_path)
    since = since or (time.time() - 3600)
    query = """
        SELECT
            CAST((timestamp / ?) AS INTEGER) * ? as bucket,
            COUNT(*) as total,
            SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity='low' THEN 1 ELSE 0 END) as low
        FROM events WHERE timestamp >= ?
    """
    params = [bucket_sec, bucket_sec, since]
    if until:
        query += " AND timestamp <= ?"
        params.append(until)
    query += " GROUP BY bucket ORDER BY bucket ASC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def failed_logins(since=None, until=None, db_path=None):
    conn = get_conn(db_path)
    since = since or (time.time() - 3600)
    query = """
        SELECT source_ip, username, COUNT(*) as attempts, country, city
        FROM events WHERE event_type='auth_failure' AND timestamp >= ?
    """
    params = [since]
    if until:
        query += " AND timestamp <= ?"
        params.append(until)
    query += " GROUP BY source_ip, username ORDER BY attempts DESC LIMIT 25"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def protocol_breakdown(since=None, until=None, db_path=None):
    conn = get_conn(db_path)
    since = since or (time.time() - 3600)
    query = """
        SELECT protocol, COUNT(*) as cnt FROM events
        WHERE timestamp >= ? AND protocol IS NOT NULL
    """
    params = [since]
    if until:
        query += " AND timestamp <= ?"
        params.append(until)
    query += " GROUP BY protocol ORDER BY cnt DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return {r["protocol"]: r["cnt"] for r in rows}


def port_targets(since=None, until=None, limit=10, db_path=None):
    conn = get_conn(db_path)
    since = since or (time.time() - 3600)
    query = """
        SELECT dest_port, COUNT(*) as cnt FROM events
        WHERE timestamp >= ? AND dest_port IS NOT NULL
    """
    params = [since]
    if until:
        query += " AND timestamp <= ?"
        params.append(until)
    query += " GROUP BY dest_port ORDER BY cnt DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return {str(r["dest_port"]): r["cnt"] for r in rows}


def mitre_breakdown(since=None, until=None, db_path=None):
    conn = get_conn(db_path)
    since = since or (time.time() - 3600)
    query = """
        SELECT mitre_tactic, mitre_technique, COUNT(*) as cnt
        FROM events WHERE timestamp >= ? AND mitre_tactic IS NOT NULL
    """
    params = [since]
    if until:
        query += " AND timestamp <= ?"
        params.append(until)
    query += " GROUP BY mitre_tactic, mitre_technique ORDER BY cnt DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def threat_intel_hits(db_path=None):
    conn = get_conn(db_path)
    rows = conn.execute("SELECT * FROM threat_intel ORDER BY last_seen DESC LIMIT 20").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def dashboard_stats(since=None, until=None, db_path=None):
    conn = get_conn(db_path)
    since = since or (time.time() - 3600)
    s = {}

    base = " FROM events WHERE timestamp >= ?"
    params = [since]
    if until:
        base += " AND timestamp <= ?"
        params = [since, until]

    s["total_events"] = conn.execute("SELECT COUNT(*) as c" + base, params).fetchone()["c"]
    s["unique_sources"] = conn.execute("SELECT COUNT(DISTINCT source_ip) as c" + base, params).fetchone()["c"]
    s["critical_events"] = conn.execute(
        "SELECT COUNT(*) as c" + base + " AND severity='critical'", params
    ).fetchone()["c"]
    s["high_events"] = conn.execute(
        "SELECT COUNT(*) as c" + base + " AND severity='high'", params
    ).fetchone()["c"]
    s["failed_logins"] = conn.execute(
        "SELECT COUNT(*) as c" + base + " AND event_type='auth_failure'", params
    ).fetchone()["c"]
    s["threat_intel_matches"] = conn.execute(
        "SELECT COUNT(*) as c" + base + " AND flagged=1", params
    ).fetchone()["c"]

    alert_base = " FROM alerts WHERE timestamp >= ?"
    alert_params = [since]
    if until:
        alert_base += " AND timestamp <= ?"
        alert_params = [since, until]

    s["total_alerts"] = conn.execute("SELECT COUNT(*) as c" + alert_base, alert_params).fetchone()["c"]
    s["unacked_alerts"] = conn.execute(
        "SELECT COUNT(*) as c" + alert_base + " AND acknowledged=0", alert_params
    ).fetchone()["c"]

    conn.close()
    return s


def acknowledge_alert(alert_id, db_path=None):
    conn = get_conn(db_path)
    conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()


def add_analyst_note(alert_id, note, db_path=None):
    conn = get_conn(db_path)
    conn.execute("UPDATE alerts SET analyst_notes=? WHERE id=?", (note, alert_id))
    conn.commit()
    conn.close()


def count_recent_by_ip(source_ip, event_type, window, db_path=None):
    conn = get_conn(db_path)
    since = time.time() - window
    row = conn.execute("""
        SELECT COUNT(*) as c FROM events
        WHERE source_ip=? AND event_type=? AND timestamp>?
    """, (source_ip, event_type, since)).fetchone()
    conn.close()
    return row["c"]


def distinct_ports_by_ip(source_ip, window, db_path=None):
    conn = get_conn(db_path)
    since = time.time() - window
    row = conn.execute("""
        SELECT COUNT(DISTINCT dest_port) as c FROM events
        WHERE source_ip=? AND timestamp>? AND dest_port IS NOT NULL
    """, (source_ip, since)).fetchone()
    conn.close()
    return row["c"]


def count_recent_events(window, db_path=None):
    conn = get_conn(db_path)
    since = time.time() - window
    row = conn.execute("SELECT COUNT(*) as c FROM events WHERE timestamp>?", (since,)).fetchone()
    conn.close()
    return row["c"]
