/* Analytics page — KPIs + Chart.js trend / severity charts + top attackers list. */
(function () {
  const api = window.AisecAPI;
  if (!api) return;
  if (!api.isAuthenticated()) { window.location.href = "login.html"; return; }
  api.applyRbac && api.applyRbac();

  const $ = (id) => document.getElementById(id);
  let trendChart = null, sevChart = null;

  // Backend serialises rows from native queries with lowercase column names.
  const pickDay   = r => r.day || r.DAY;
  const pickCount = r => Number(r.count || r.COUNT || 0);
  const pickIp    = r => r.ip  || r.IP;
  const pickSev   = r => r.severity || r.SEVERITY;

  async function load() {
    const days = +$("anRange").value;
    try {
      const data = await api.analyticsSummary(days);
      renderKpis(data);
      renderTrend(data.trend || []);
      renderSeverity(data.severity_trend || data.severityTrend || []);
      renderAttackers(data.top_attackers || data.topAttackers || []);
    } catch (e) {
      console.error("Analytics load failed:", e);
      $("kMttr").textContent = "—";
    }
  }

  function renderKpis(data) {
    const m = data.mttr || {};
    $("kMttr").textContent = m.human_readable || m.humanReadable || "n/a";

    const trend = data.trend || [];
    const total = trend.reduce((s, r) => s + pickCount(r), 0);
    $("kTotal").textContent = total.toLocaleString();
    $("kTotalSub").textContent = `over last ${data.days} days`;

    let peak = { day: "—", count: 0 };
    trend.forEach(r => { const c = pickCount(r); if (c > peak.count) peak = { day: pickDay(r), count: c }; });
    $("kPeak").textContent = peak.count;
    $("kPeakSub").textContent = peak.day !== "—" ? `on ${peak.day}` : "no alerts in window";

    const attackers = data.top_attackers || data.topAttackers || [];
    $("kUniq").textContent = attackers.length;
  }

  function renderTrend(rows) {
    const labels = rows.map(pickDay);
    const counts = rows.map(pickCount);
    const ctx = $("trendChart").getContext("2d");
    if (trendChart) trendChart.destroy();
    trendChart = new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [{
          label: "Alerts per day",
          data: counts,
          borderColor: "#22b8cf",
          backgroundColor: "rgba(34,184,207,.15)",
          fill: true, tension: .3, pointRadius: 3
        }]
      },
      options: chartOpts()
    });
  }

  function renderSeverity(rows) {
    // Pivot rows of {day, severity, count} into per-severity series.
    const days = [...new Set(rows.map(pickDay))].sort();
    const severities = ["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL"];
    const colors = {
      CRITICAL:"#dc2626", HIGH:"#ea580c", MEDIUM:"#ca8a04",
      LOW:"#16a34a", INFORMATIONAL:"#6b7280"
    };
    const datasets = severities.map(sev => ({
      label: sev,
      data: days.map(d => {
        const r = rows.find(x => pickDay(x) === d && pickSev(x) === sev);
        return r ? pickCount(r) : 0;
      }),
      borderColor: colors[sev],
      backgroundColor: colors[sev] + "33",
      fill: false, tension: .3, pointRadius: 2
    }));
    const ctx = $("sevChart").getContext("2d");
    if (sevChart) sevChart.destroy();
    sevChart = new Chart(ctx, {
      type: "line",
      data: { labels: days, datasets },
      options: chartOpts(true)
    });
  }

  function renderAttackers(rows) {
    if (!rows.length) {
      $("attackers").innerHTML = '<div class="muted" style="text-align:center;padding:20px">No attackers in the last 7 days. Quiet network ✨</div>';
      return;
    }
    $("attackers").innerHTML = rows.map(r => `
      <div class="an-row">
        <span class="ip"><i class="fa-solid fa-globe" style="color:#8ea0b8;margin-right:8px"></i>${escape(pickIp(r))}</span>
        <span class="cnt">${pickCount(r).toLocaleString()} alerts</span>
      </div>`).join("");
  }

  function chartOpts(stacked) {
    return {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: "#cbd5e1", boxWidth: 12 } }
      },
      scales: {
        x: { ticks: { color: "#8ea0b8" }, grid: { color: "rgba(255,255,255,.05)" } },
        y: { beginAtZero: true, ticks: { color: "#8ea0b8" }, grid: { color: "rgba(255,255,255,.05)" } }
      }
    };
  }

  function escape(s) {
    if (s == null) return "";
    return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
  }

  $("anRange").onchange = load;
  load();
})();
