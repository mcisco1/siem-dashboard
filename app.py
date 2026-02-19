import time
import threading
from functools import wraps
from markupsafe import escape
from flask import Flask, render_template, jsonify, request, abort
from flask_socketio import SocketIO

import database as db
from log_generator import generate_batch
from correlation import correlate
from attack_scenario import AttackScenario
from config import GENERATOR_INTERVAL, LOG_BATCH_SIZE, API_TOKEN

app = Flask(__name__)
app.config["SECRET_KEY"] = "siem-dashboard-key"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

scenario = AttackScenario()


# ---- auth ----

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-API-Token") or request.args.get("token")
        if token != API_TOKEN:
            abort(401, description="Missing or invalid API token")
        return f(*args, **kwargs)
    return decorated


# ---- input helpers ----

def get_time_range():
    """Pull since/until from query params. Accepts unix timestamps or relative like '1h','30m'."""
    since = request.args.get("since", None)
    until = request.args.get("until", None)

    if since:
        since = _parse_time(since)
    if until:
        until = _parse_time(until)

    return since, until


def _parse_time(val):
    try:
        return float(val)
    except ValueError:
        pass
    # relative: 1h, 30m, 2d
    val = val.strip().lower()
    multipliers = {"m": 60, "h": 3600, "d": 86400}
    if val[-1] in multipliers and val[:-1].isdigit():
        return time.time() - int(val[:-1]) * multipliers[val[-1]]
    return None


def sanitize_str(val):
    if val is None:
        return None
    return str(escape(str(val)))


def sanitize_event(ev):
    """Escape all string fields in an event dict before sending to frontend."""
    safe = {}
    for k, v in ev.items():
        if isinstance(v, str):
            safe[k] = str(escape(v))
        else:
            safe[k] = v
    return safe


def sanitize_list(items):
    return [sanitize_event(i) for i in items]


# ---- background ingestion ----

def ingest_loop():
    while True:
        batch = generate_batch(LOG_BATCH_SIZE)

        # weave in attack scenario events
        attack_events = scenario.advance()
        if attack_events:
            batch.extend(attack_events)

        db.insert_events(batch)
        alerts = correlate(batch)

        socketio.emit("new_events", {
            "count": len(batch),
            "alerts_triggered": len(alerts),
            "stats": db.dashboard_stats(),
            "recent": sanitize_list(db.recent_events(20)),
            "severity": db.severity_counts(),
            "timeline": db.timeline_buckets(),
        })
        time.sleep(GENERATOR_INTERVAL)


# ---- routes ----

@app.route("/")
def index():
    return render_template("dashboard.html", api_token=API_TOKEN)


@app.route("/api/stats")
@require_token
def api_stats():
    since, until = get_time_range()
    return jsonify(db.dashboard_stats(since, until))


@app.route("/api/events")
@require_token
def api_events():
    limit = request.args.get("limit", 200, type=int)
    since, until = get_time_range()
    severity = sanitize_str(request.args.get("severity"))
    event_type = sanitize_str(request.args.get("event_type"))
    source_ip = sanitize_str(request.args.get("source_ip"))
    events = db.recent_events(limit, since, until, severity, event_type, source_ip)
    return jsonify(sanitize_list(events))


@app.route("/api/alerts")
@require_token
def api_alerts():
    return jsonify(sanitize_list(db.recent_alerts()))


@app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
@require_token
def api_ack_alert(alert_id):
    db.acknowledge_alert(alert_id)
    return jsonify({"status": "ok"})


@app.route("/api/alerts/<int:alert_id>/note", methods=["POST"])
@require_token
def api_add_note(alert_id):
    note = sanitize_str(request.json.get("note", ""))
    db.add_analyst_note(alert_id, note)
    return jsonify({"status": "ok"})


@app.route("/api/severity")
@require_token
def api_severity():
    since, until = get_time_range()
    return jsonify(db.severity_counts(since, until))


@app.route("/api/event-types")
@require_token
def api_event_types():
    since, until = get_time_range()
    return jsonify(db.event_type_counts(since, until))


@app.route("/api/top-sources")
@require_token
def api_top_sources():
    since, until = get_time_range()
    return jsonify(sanitize_list(db.top_sources(since=since, until=until)))


@app.route("/api/geo")
@require_token
def api_geo():
    since, until = get_time_range()
    return jsonify(sanitize_list(db.geo_breakdown(since, until)))


@app.route("/api/timeline")
@require_token
def api_timeline():
    since, until = get_time_range()
    return jsonify(db.timeline_buckets(since, until))


@app.route("/api/failed-logins")
@require_token
def api_failed_logins():
    since, until = get_time_range()
    return jsonify(sanitize_list(db.failed_logins(since, until)))


@app.route("/api/protocols")
@require_token
def api_protocols():
    since, until = get_time_range()
    return jsonify(db.protocol_breakdown(since, until))


@app.route("/api/ports")
@require_token
def api_ports():
    since, until = get_time_range()
    return jsonify(db.port_targets(since, until))


@app.route("/api/mitre")
@require_token
def api_mitre():
    since, until = get_time_range()
    return jsonify(sanitize_list(db.mitre_breakdown(since, until)))


@app.route("/api/threat-intel")
@require_token
def api_threat_intel():
    return jsonify(sanitize_list(db.threat_intel_hits()))


@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "unauthorized", "message": str(e.description)}), 401


if __name__ == "__main__":
    db.init_db()
    t = threading.Thread(target=ingest_loop, daemon=True)
    t.start()
    print(f"[*] SIEM Dashboard running on http://127.0.0.1:5000")
    print(f"[*] API Token: {API_TOKEN}")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
