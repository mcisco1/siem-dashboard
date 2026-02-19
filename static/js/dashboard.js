const socket = io();

const COLORS = {
    critical: "#ef4444", high: "#f97316", medium: "#eab308",
    low: "#22c55e", accent: "#3b82f6", dim: "#94a3b8",
    grid: "rgba(148,163,184,0.08)",
};

const chartDefaults = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: COLORS.dim, font: { size: 11 } } } },
    scales: {
        x: { ticks: { color: COLORS.dim, font: { size: 10 } }, grid: { color: COLORS.grid } },
        y: { ticks: { color: COLORS.dim, font: { size: 10 } }, grid: { color: COLORS.grid } },
    },
};

// ---- safe text helper (prevents xss in DOM writes) ----

function safeText(str) {
    if (str === null || str === undefined) return "";
    const d = document.createElement("div");
    d.textContent = String(str);
    return d.innerHTML;
}

// ---- filter state ----

function getTimeRange() {
    const sel = document.getElementById("time-range").value;
    if (sel === "custom") {
        const from = document.getElementById("range-from").value;
        const to = document.getElementById("range-to").value;
        return {
            since: from ? (new Date(from).getTime() / 1000).toString() : "",
            until: to ? (new Date(to).getTime() / 1000).toString() : "",
        };
    }
    return { since: sel, until: "" };
}

function getFilters() {
    return {
        severity: document.getElementById("filter-severity").value,
        event_type: document.getElementById("filter-type").value,
        source_ip: document.getElementById("filter-ip").value.trim(),
    };
}

function buildQuery(extra) {
    const { since, until } = getTimeRange();
    const params = new URLSearchParams();
    params.set("token", API_TOKEN);
    if (since) params.set("since", since);
    if (until) params.set("until", until);
    if (extra) {
        for (const [k, v] of Object.entries(extra)) {
            if (v) params.set(k, v);
        }
    }
    return params.toString();
}

// toggle custom date inputs
document.getElementById("time-range").addEventListener("change", function() {
    document.getElementById("custom-range").style.display =
        this.value === "custom" ? "flex" : "none";
});

// ---- charts ----

const timelineChart = new Chart(document.getElementById("timelineChart"), {
    type: "line",
    data: {
        labels: [],
        datasets: [
            { label: "Critical", data: [], borderColor: COLORS.critical, backgroundColor: "rgba(239,68,68,0.1)", fill: true, tension: 0.3, pointRadius: 0 },
            { label: "High", data: [], borderColor: COLORS.high, backgroundColor: "rgba(249,115,22,0.1)", fill: true, tension: 0.3, pointRadius: 0 },
            { label: "Medium", data: [], borderColor: COLORS.medium, backgroundColor: "rgba(234,179,8,0.05)", fill: true, tension: 0.3, pointRadius: 0 },
            { label: "Low", data: [], borderColor: COLORS.low, backgroundColor: "rgba(34,197,94,0.05)", fill: true, tension: 0.3, pointRadius: 0 },
        ],
    },
    options: { ...chartDefaults, plugins: { ...chartDefaults.plugins, title: { display: false } } },
});

const severityChart = new Chart(document.getElementById("severityChart"), {
    type: "doughnut",
    data: {
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [{ data: [0, 0, 0, 0], backgroundColor: [COLORS.critical, COLORS.high, COLORS.medium, COLORS.low], borderWidth: 0 }],
    },
    options: {
        responsive: true, maintainAspectRatio: false, cutout: "65%",
        plugins: { legend: { position: "right", labels: { color: COLORS.dim, padding: 12, font: { size: 12 } } } },
    },
});

const eventTypeChart = new Chart(document.getElementById("eventTypeChart"), {
    type: "bar",
    data: { labels: [], datasets: [{ data: [], backgroundColor: COLORS.accent, borderRadius: 4, barThickness: 18 }] },
    options: { ...chartDefaults, indexAxis: "y", plugins: { ...chartDefaults.plugins, legend: { display: false } } },
});

const protoChart = new Chart(document.getElementById("protoChart"), {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], backgroundColor: ["#3b82f6", "#8b5cf6", "#06b6d4", "#f43f5e", "#10b981"], borderWidth: 0 }] },
    options: {
        responsive: true, maintainAspectRatio: false, cutout: "60%",
        plugins: { legend: { position: "right", labels: { color: COLORS.dim, font: { size: 12 } } } },
    },
});

const portChart = new Chart(document.getElementById("portChart"), {
    type: "bar",
    data: { labels: [], datasets: [{ data: [], backgroundColor: "#8b5cf6", borderRadius: 4, barThickness: 20 }] },
    options: { ...chartDefaults, plugins: { ...chartDefaults.plugins, legend: { display: false } } },
});

// ---- leaflet map ----

const map = L.map("geomap", { zoomControl: true, attributionControl: false }).setView([25, 0], 2);
L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", { maxZoom: 18 }).addTo(map);
let mapMarkers = [];

function updateMap(geodata) {
    mapMarkers.forEach(m => map.removeLayer(m));
    mapMarkers = [];
    geodata.forEach(g => {
        if (!g.lat || !g.lng) return;
        let color = g.threats > 3 ? COLORS.critical : g.threats > 0 ? COLORS.high : COLORS.accent;
        let radius = Math.min(Math.max(g.cnt / 3, 5), 25);
        let marker = L.circleMarker([g.lat, g.lng], {
            radius, color, fillColor: color, fillOpacity: 0.4, weight: 1,
        }).addTo(map);
        marker.bindPopup(`<b>${safeText(g.city)}, ${safeText(g.country)}</b><br>Events: ${g.cnt}<br>High/Crit: ${g.threats}`);
        mapMarkers.push(marker);
    });
}

// ---- rendering ----

function fmtTime(ts) {
    return new Date(ts * 1000).toLocaleTimeString("en-US", { hour12: false });
}

function sevBadge(sev) {
    return `<span class="sev-badge sev-${safeText(sev)}">${safeText(sev)}</span>`;
}

function updateStats(s) {
    document.getElementById("stat-total").textContent = (s.total_events || 0).toLocaleString();
    document.getElementById("stat-critical").textContent = (s.critical_events || 0).toLocaleString();
    document.getElementById("stat-high").textContent = (s.high_events || 0).toLocaleString();
    document.getElementById("stat-sources").textContent = (s.unique_sources || 0).toLocaleString();
    document.getElementById("stat-alerts").textContent = (s.unacked_alerts || 0).toLocaleString();
    document.getElementById("stat-logins").textContent = (s.failed_logins || 0).toLocaleString();
    document.getElementById("stat-intel").textContent = (s.threat_intel_matches || 0).toLocaleString();
}

function updateTimeline(data) {
    timelineChart.data.labels = data.map(d => fmtTime(d.bucket));
    timelineChart.data.datasets[0].data = data.map(d => d.critical);
    timelineChart.data.datasets[1].data = data.map(d => d.high);
    timelineChart.data.datasets[2].data = data.map(d => d.medium);
    timelineChart.data.datasets[3].data = data.map(d => d.low);
    timelineChart.update("none");
}

function updateSeverity(data) {
    severityChart.data.datasets[0].data = [data.critical || 0, data.high || 0, data.medium || 0, data.low || 0];
    severityChart.update("none");
}

function updateEventFeed(events) {
    const feed = document.getElementById("event-feed");
    let html = "";
    events.forEach(ev => {
        let flag = ev.flagged ? ' <span class="feed-flag">⚑ THREAT INTEL</span>' : "";
        html += `<div class="feed-line sev-${safeText(ev.severity)}">` +
            `<span class="feed-ts">${fmtTime(ev.timestamp)}</span>` +
            `<span class="feed-ip">${safeText(ev.source_ip)}</span>` +
            `${safeText(ev.message)}${flag}</div>`;
    });
    feed.innerHTML = html;
}

function renderEventTypes(data) {
    const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 10);
    eventTypeChart.data.labels = sorted.map(e => e[0].replace(/_/g, " "));
    eventTypeChart.data.datasets[0].data = sorted.map(e => e[1]);
    eventTypeChart.update("none");
}

function renderSources(data) {
    document.querySelector("#sources-table tbody").innerHTML = data.map(s =>
        `<tr><td>${safeText(s.source_ip)}</td><td>${safeText(s.country) || "—"}</td>` +
        `<td>${safeText(s.city) || "—"}</td><td>${s.total}</td><td>${s.high_sev}</td></tr>`
    ).join("");
}

function renderLogins(data) {
    document.querySelector("#logins-table tbody").innerHTML = data.map(l =>
        `<tr><td>${safeText(l.source_ip)}</td><td>${safeText(l.username)}</td>` +
        `<td>${l.attempts}</td><td>${safeText(l.city) || ""}, ${safeText(l.country) || ""}</td></tr>`
    ).join("");
}

function renderAlerts(data) {
    const tbody = document.querySelector("#alerts-table tbody");
    const unacked = data.filter(a => !a.acknowledged).length;
    document.getElementById("alert-badge").textContent = unacked;

    tbody.innerHTML = data.map(a => {
        const ackBtn = a.acknowledged
            ? `<button class="btn-ack acked">✓</button>`
            : `<button class="btn-ack" onclick="ackAlert(${a.id})">ACK</button>`;
        return `<tr><td>${fmtTime(a.timestamp)}</td><td>${safeText(a.alert_type).replace(/_/g, " ")}</td>` +
            `<td>${sevBadge(a.severity)}</td><td>${safeText(a.source_ip)}</td>` +
            `<td>${safeText(a.description)}</td><td>${safeText(a.mitre_technique) || "—"}</td>` +
            `<td>${a.event_count}</td><td>${ackBtn}</td></tr>`;
    }).join("");
}

function renderProtocols(data) {
    protoChart.data.labels = Object.keys(data);
    protoChart.data.datasets[0].data = Object.values(data);
    protoChart.update("none");
}

function renderPorts(data) {
    const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 10);
    portChart.data.labels = sorted.map(p => ":" + p[0]);
    portChart.data.datasets[0].data = sorted.map(p => p[1]);
    portChart.update("none");
}

function renderMitre(data) {
    const grid = document.getElementById("mitre-grid");
    if (!data.length) {
        grid.innerHTML = '<div style="color:var(--text-dim)">Waiting for correlated events...</div>';
        return;
    }
    grid.innerHTML = data.map(m =>
        `<div class="mitre-card"><div class="mitre-tech">${safeText(m.mitre_technique)}</div>` +
        `<div class="mitre-tactic">${safeText(m.mitre_tactic)}</div>` +
        `<div class="mitre-count">${m.cnt}</div></div>`
    ).join("");
}

function renderIntel(data) {
    const tbody = document.querySelector("#intel-table tbody");
    if (!data.length) {
        tbody.innerHTML = '<tr><td colspan="4" style="color:var(--text-dim)">No matches yet</td></tr>';
        return;
    }
    tbody.innerHTML = data.map(i =>
        `<tr><td>${safeText(i.ip)}</td><td>${safeText(i.threat_type)}</td>` +
        `<td>${i.hit_count}</td><td>${fmtTime(i.last_seen)}</td></tr>`
    ).join("");
}

// ---- data fetch (respects filters) ----

async function fetchAll() {
    try {
        const filters = getFilters();
        const q = buildQuery();
        const qf = buildQuery(filters);

        const [stats, events, alerts, severity, types, sources, geo, timeline, logins, protos, ports, mitre, intel] =
            await Promise.all([
                fetch(`/api/stats?${q}`).then(r => r.json()),
                fetch(`/api/events?limit=80&${qf}`).then(r => r.json()),
                fetch(`/api/alerts?${q}`).then(r => r.json()),
                fetch(`/api/severity?${q}`).then(r => r.json()),
                fetch(`/api/event-types?${q}`).then(r => r.json()),
                fetch(`/api/top-sources?${q}`).then(r => r.json()),
                fetch(`/api/geo?${q}`).then(r => r.json()),
                fetch(`/api/timeline?${q}`).then(r => r.json()),
                fetch(`/api/failed-logins?${q}`).then(r => r.json()),
                fetch(`/api/protocols?${q}`).then(r => r.json()),
                fetch(`/api/ports?${q}`).then(r => r.json()),
                fetch(`/api/mitre?${q}`).then(r => r.json()),
                fetch(`/api/threat-intel?${q}`).then(r => r.json()),
            ]);

        updateStats(stats);
        updateTimeline(timeline);
        updateSeverity(severity);
        updateEventFeed(events);
        renderEventTypes(types);
        renderSources(sources);
        renderAlerts(alerts);
        renderLogins(logins);
        renderProtocols(protos);
        renderPorts(ports);
        renderMitre(mitre);
        renderIntel(intel);
        updateMap(geo);
    } catch (err) {
        console.error("fetch error:", err);
    }
}

// ---- alert actions ----

async function ackAlert(id) {
    await fetch(`/api/alerts/${id}/ack?token=${API_TOKEN}`, { method: "POST" });
    fetchAll();
}

// ---- websocket live updates ----

socket.on("new_events", data => {
    if (data.stats) updateStats(data.stats);
    if (data.timeline) updateTimeline(data.timeline);
    if (data.severity) updateSeverity(data.severity);
    if (data.recent) updateEventFeed(data.recent);
});

socket.on("connect", () => { document.getElementById("conn-status").textContent = "LIVE"; });
socket.on("disconnect", () => { document.getElementById("conn-status").textContent = "OFFLINE"; });

// ---- clock ----

function updateClock() {
    document.getElementById("clock").textContent =
        new Date().toLocaleString("en-US", { hour12: false, month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// ---- init ----

fetchAll();
setInterval(fetchAll, 8000);
setInterval(updateClock, 1000);
updateClock();
