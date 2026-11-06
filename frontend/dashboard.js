// ── API Base URL ────────────────────────────────────────────
// Change 5000 to 5001 if you changed the port earlier
const API = "http://127.0.0.1:5001";

// ── Chart instances (stored so we can destroy and redraw) ───
let threatLevelChart = null;
let timelineChart    = null;

// ── Colour map for threat levels ────────────────────────────
const LEVEL_COLORS = {
  LOW     : "#5b8a72",
  MEDIUM  : "#c9952c",
  HIGH    : "#c0654a",
  CRITICAL: "#9c3b30"
};

// ════════════════════════════════════════════════════════════
// LOAD ALL DATA — called on page load and on refresh button
// ════════════════════════════════════════════════════════════
async function loadAllData() {
  showLoadingState();
  try {
    await Promise.all([
      loadStats(),
      loadThreatLevelChart(),
      loadTimelineChart(),
      loadTopIPs(),
      loadAlerts(),
      loadLogs()
    ]);
  } catch (err) {
    console.error("Error loading data:", err);
    showError("Could not connect to API. Make sure Flask server is running.");
  }
}

// ════════════════════════════════════════════════════════════
// STATS CARDS
// ════════════════════════════════════════════════════════════
async function loadStats() {
  const res  = await fetch(`${API}/api/stats`);
  const json = await res.json();
  const d    = json.data;

  document.getElementById("total-logs").textContent      = d.total_logs.toLocaleString();
  document.getElementById("total-anomalies").textContent = d.total_anomalies.toLocaleString();
  document.getElementById("total-alerts").textContent    = d.total_alerts.toLocaleString();
  document.getElementById("suspicious-ips").textContent  = d.suspicious_ips.toLocaleString();
  document.getElementById("avg-score").textContent       = d.avg_threat_score;
  document.getElementById("max-score").textContent       = d.max_threat_score;
}

// ════════════════════════════════════════════════════════════
// THREAT LEVEL DOUGHNUT CHART
// ════════════════════════════════════════════════════════════
async function loadThreatLevelChart() {
  const res  = await fetch(`${API}/api/stats`);
  const json = await res.json();
  const lvls = json.data.threat_levels;

  const labels = ["Low", "Medium", "High", "Critical"];
  const values = [lvls.LOW, lvls.MEDIUM, lvls.HIGH, lvls.CRITICAL];
  const colors = [
    LEVEL_COLORS.LOW,
    LEVEL_COLORS.MEDIUM,
    LEVEL_COLORS.HIGH,
    LEVEL_COLORS.CRITICAL
  ];

  if (threatLevelChart) threatLevelChart.destroy();

  const ctx = document.getElementById("threatLevelChart").getContext("2d");
  threatLevelChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels  : labels,
      datasets: [{
        data           : values,
        backgroundColor: colors.map(c => c + "cc"),
        borderColor    : colors,
        borderWidth    : 2,
        hoverOffset    : 8
      }]
    },
    options: {
      responsive         : true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels  : { color: "#8892a4", padding: 16, font: { size: 12 } }
        }
      },
      cutout: "65%"
    }
  });
}

// ════════════════════════════════════════════════════════════
// TIMELINE LINE CHART — threats by hour
// ════════════════════════════════════════════════════════════
async function loadTimelineChart() {
  const res  = await fetch(`${API}/api/threats/timeline`);
  const json = await res.json();
  const data = json.data;

  const labels    = data.map(d => d.label);
  const totals    = data.map(d => d.total);
  const anomalies = data.map(d => d.anomalies);
  const avgScores = data.map(d => d.avg_score);

  if (timelineChart) timelineChart.destroy();

  const ctx = document.getElementById("timelineChart").getContext("2d");
  timelineChart = new Chart(ctx, {
    type: "line",
    data: {
      labels  : labels,
      datasets: [
       {
          label          : "Total Events",
          data           : totals,
          borderColor    : "#6b8fa3",
          backgroundColor: "rgba(107,143,163,0.1)",
          fill           : true,
          tension        : 0.4,
          pointRadius    : 3
        },
        {
          label          : "Anomalies",
          data           : anomalies,
          borderColor    : "#c0654a",
          backgroundColor: "rgba(192,101,74,0.1)",
          fill           : true,
          tension        : 0.4,
          pointRadius    : 3
        },
        {
          label          : "Avg Threat Score",
          data           : avgScores,
          borderColor    : "#c9952c",
          backgroundColor: "rgba(201,149,44,0.05)",
          fill           : false,
          tension        : 0.4,
          pointRadius    : 3,
          yAxisID        : "y2"
        }
      ]
    },
    options: {
      responsive         : true,
      maintainAspectRatio: false,
      interaction        : { mode: "index", intersect: false },
      plugins: {
        legend: {
          labels: { color: "#8892a4", font: { size: 12 } }
        }
      },
      scales: {
        x: {
          ticks: { color: "#8892a4", font: { size: 11 } },
          grid : { color: "rgba(255,255,255,0.05)" }
        },
        y: {
          ticks: { color: "#8892a4", font: { size: 11 } },
          grid : { color: "rgba(255,255,255,0.05)" }
        },
        y2: {
          position: "right",
          ticks   : { color: "#c9952c", font: { size: 11 } },
          grid    : { display: false }
        }
      }
    }
  });
}

// ════════════════════════════════════════════════════════════
// TOP SUSPICIOUS IPs TABLE
// ════════════════════════════════════════════════════════════
async function loadTopIPs() {
  const res  = await fetch(`${API}/api/threats/top-ips`);
  const json = await res.json();
  const tbody = document.getElementById("ip-table-body");

  if (!json.data || json.data.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="loading">No data found</td></tr>`;
    return;
  }

  tbody.innerHTML = json.data.map(ip => `
    <tr>
      <td><code style="color:#60a5fa">${ip.ip_address}</code></td>
      <td>${ip.total_attempts}</td>
      <td>
        <div class="score-bar-wrapper">
          <div class="score-bar">
            <div class="score-bar-fill"
                 style="width:${ip.max_score}%;
                        background:${LEVEL_COLORS[ip.highest_level] || '#6b7280'}">
            </div>
          </div>
          <span class="score-text"
                style="color:${LEVEL_COLORS[ip.highest_level] || '#6b7280'}">
            ${ip.max_score}
          </span>
        </div>
      </td>
      <td><span class="badge badge-${ip.highest_level}">${ip.highest_level}</span></td>
    </tr>
  `).join("");
}

// ════════════════════════════════════════════════════════════
// LIVE ALERTS
// ════════════════════════════════════════════════════════════
async function loadAlerts() {
  const res  = await fetch(`${API}/api/alerts?limit=20`);
  const json = await res.json();
  const container = document.getElementById("alerts-list");

  if (!json.data || json.data.length === 0) {
    container.innerHTML = `<p class="loading">No alerts found</p>`;
    return;
  }

  container.innerHTML = json.data.map(alert => `
    <div class="alert-item ${alert.threat_level}">
      <div class="alert-header">
        <span class="alert-ip">
          <span class="badge badge-${alert.threat_level}">${alert.threat_level}</span>
          &nbsp;${alert.ip_address}
        </span>
        <span class="alert-time">${alert.timestamp}</span>
      </div>
      <div class="alert-desc">${alert.description}</div>
    </div>
  `).join("");
}

// ════════════════════════════════════════════════════════════
// LOGS TABLE
// ════════════════════════════════════════════════════════════
async function loadLogs(level = "") {
  let url = `${API}/api/logs?limit=50`;
  if (level) url += `&level=${level}`;

  const res  = await fetch(url);
  const json = await res.json();
  const tbody = document.getElementById("logs-table-body");

  if (!json.data || json.data.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="loading">No logs found</td></tr>`;
    return;
  }

  tbody.innerHTML = json.data.map(log => `
    <tr>
      <td style="color:var(--text-muted);font-size:12px">${log.timestamp}</td>
      <td><code style="color:#60a5fa">${log.ip_address}</code></td>
      <td>${log.username}</td>
      <td>
        <span class="${log.status === 'Accepted' ? 'status-accepted' : 'status-failed'}">
          ${log.status === 'Accepted' ? '✓' : '✗'} ${log.status}
        </span>
      </td>
      <td style="text-align:center">${log.failed_attempts}</td>
      <td>
        <div class="score-bar-wrapper">
          <div class="score-bar">
            <div class="score-bar-fill"
                 style="width:${log.threat_score}%;
                        background:${LEVEL_COLORS[log.threat_level] || '#6b7280'}">
            </div>
          </div>
          <span class="score-text"
                style="color:${LEVEL_COLORS[log.threat_level] || '#6b7280'}">
            ${log.threat_score}
          </span>
        </div>
      </td>
      <td><span class="badge badge-${log.threat_level}">${log.threat_level}</span></td>
    </tr>
  `).join("");
}

// ════════════════════════════════════════════════════════════
// FILTER LOGS BY LEVEL
// ════════════════════════════════════════════════════════════
function filterLogs() {
  const level = document.getElementById("level-filter").value;
  loadLogs(level);
}

// ════════════════════════════════════════════════════════════
// ANALYSE SINGLE LOG ENTRY
// ════════════════════════════════════════════════════════════
async function analyseLog() {
  const ip       = document.getElementById("f-ip").value.trim();
  const user     = document.getElementById("f-user").value.trim();
  const status   = document.getElementById("f-status").value;
  const attempts = parseInt(document.getElementById("f-attempts").value) || 1;
  const port     = parseInt(document.getElementById("f-port").value)     || 22;
  const hour     = parseInt(document.getElementById("f-hour").value)     || 12;

  if (!ip || !user) {
    alert("Please enter an IP address and username.");
    return;
  }

  const btn = document.querySelector(".analyse-btn");
  btn.textContent = "⏳ Analysing…";
  btn.disabled    = true;

  try {
    const res = await fetch(`${API}/api/analyse`, {
      method : "POST",
      headers: { "Content-Type": "application/json" },
      body   : JSON.stringify({
        ip_address      : ip,
        username        : user,
        status          : status,
        failed_attempts : attempts,
        port            : port,
        hour            : hour
      })
    });

    const json   = await res.json();
    const result = json.result;

    const scoreEl  = document.getElementById("result-score");
    const levelEl  = document.getElementById("result-level");
    const detailEl = document.getElementById("result-detail");
    const boxEl    = document.getElementById("result-box");

    const color = LEVEL_COLORS[result.threat_level] || "#6b7280";

    scoreEl.textContent  = result.threat_score;
    scoreEl.style.color  = color;
    levelEl.textContent  = result.threat_level;
    levelEl.style.color  = color;
    detailEl.textContent = `Anomaly detected: ${result.is_anomaly ? "YES ⚠️" : "No ✓"} | Score: ${result.threat_score}/100`;

    boxEl.style.display     = "flex";
    boxEl.style.borderColor = color;

  } catch (err) {
    alert("Error connecting to API. Make sure Flask server is running.");
  } finally {
    btn.textContent = "🤖 Analyse with AI";
    btn.disabled    = false;
  }
}

// ════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════
function showLoadingState() {
  document.getElementById("total-logs").textContent      = "…";
  document.getElementById("total-anomalies").textContent = "…";
  document.getElementById("total-alerts").textContent    = "…";
  document.getElementById("suspicious-ips").textContent  = "…";
  document.getElementById("avg-score").textContent       = "…";
  document.getElementById("max-score").textContent       = "…";
}

function showError(msg) {
  document.getElementById("alerts-list").innerHTML =
   `<p style="color:#c0654a;padding:16px">${msg}</p>`;
}

// ── Start loading when page opens ───────────────────────────
document.addEventListener("DOMContentLoaded", loadAllData);