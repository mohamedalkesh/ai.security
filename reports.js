// Reveal
const io = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting){ e.target.classList.add('visible'); io.unobserve(e.target); }});
}, { threshold:.08 });
document.querySelectorAll('.reveal').forEach(el => io.observe(el));

// Animate counters
document.querySelectorAll('[data-target]').forEach(el => {
  const target = parseFloat(el.dataset.target);
  const isFloat = el.dataset.float === '1';
  const dur = 1400;
  const start = performance.now();
  (function tick(now){
    const p = Math.min((now-start)/dur, 1);
    const e = 1 - Math.pow(1-p,3);
    const v = target * e;
    el.textContent = isFloat ? v.toFixed(1) : Math.floor(v).toLocaleString();
    if (p<1) requestAnimationFrame(tick);
  })(performance.now());
});

// ===== Incident Trends (grouped bar) =====
const MONTHS_4 = ['Jan','Feb','Mar','Apr'];
const MONTHS_6 = ['Nov','Dec','Jan','Feb','Mar','Apr'];
const MONTHS_12 = ['May','Jun','Jul','Aug','Sep','Oct','Nov','Dec','Jan','Feb','Mar','Apr'];
const incData  = [0, 0, 0, 0];
const blkData  = [0, 0, 0, 0];

const trendCtx = document.getElementById('trendChart').getContext('2d');
const trendChart = new Chart(trendCtx, {
  type:'bar',
  data:{
    labels:MONTHS_4,
    datasets:[
      { label:'Incidents', data:incData, backgroundColor:'#ff6b6b', borderRadius:6, barPercentage:.7, categoryPercentage:.5 },
      { label:'Blocked',   data:blkData, backgroundColor:'#22b8cf', borderRadius:6, barPercentage:.7, categoryPercentage:.5 },
    ]
  },
  options:{
    responsive:true, maintainAspectRatio:false,
    interaction:{ mode:'index', intersect:false },
    plugins:{
      legend:{display:false},
      tooltip:{
        backgroundColor:'#0f1d35', borderColor:'rgba(34,184,207,.4)', borderWidth:1,
        padding:14, titleColor:'#22b8cf', bodyColor:'#e6edf7', cornerRadius:10,
        titleFont:{size:13,weight:'700'}, bodyFont:{size:12},
        callbacks:{
          label:(c) => ` ${c.dataset.label}: ${c.parsed.y}`
        }
      }
    },
    scales:{
      x:{ grid:{color:'rgba(255,255,255,.04)'}, ticks:{color:'#8ea0b8'} },
      y:{ grid:{color:'rgba(255,255,255,.05)'}, ticks:{color:'#8ea0b8',stepSize:20}, beginAtZero:true }
    },
    animation:{duration:1400, easing:'easeOutCubic'}
  }
});

document.getElementById('trendRange').addEventListener('change', (e) => {
  const v = e.target.value;
  let labels, f;
  if (v.includes('12')){ labels = MONTHS_12; f = 12; }
  else if (v.includes('6')){ labels = MONTHS_6; f = 6; }
  else { labels = MONTHS_4; f = 4; }
  const inc = labels.map((_,i) => Math.round(30 + Math.random()*50 + i));
  const blk = inc.map(v => v - Math.floor(Math.random()*4));
  trendChart.data.labels = labels;
  trendChart.data.datasets[0].data = inc;
  trendChart.data.datasets[1].data = blk;
  trendChart.update();
});

// ===== Threat Distribution Donut =====
// Threat distribution — populated from /api/alerts/breakdown by the backend hook below.
const DIST = [{ label:'No data', pct:100, color:'#334155' }];
const distCtx = document.getElementById('distChart').getContext('2d');
new Chart(distCtx, {
  type:'doughnut',
  data:{
    labels:DIST.map(d=>d.label),
    datasets:[{
      data:DIST.map(d=>d.pct),
      backgroundColor:DIST.map(d=>d.color),
      borderColor:'#16243d', borderWidth:3, hoverOffset:10,
    }]
  },
  options:{
    responsive:true, maintainAspectRatio:false, cutout:'70%',
    plugins:{
      legend:{display:false},
      tooltip:{
        backgroundColor:'#0f1d35', borderColor:'rgba(34,184,207,.4)', borderWidth:1,
        padding:12, titleColor:'#22b8cf', bodyColor:'#e6edf7',
        callbacks:{ label:(c) => ` ${c.parsed}% of threats` }
      }
    },
    animation:{animateRotate:true, animateScale:true, duration:1400}
  }
});

document.getElementById('distLegend').innerHTML = DIST.map(d => `
  <li>
    <span class="swatch" style="background:${d.color}"></span>
    <span>${d.label}</span>
    <span class="pct">${d.pct}%</span>
  </li>
`).join('');

// ===== Recent Reports =====
const REPORTS = [];
document.getElementById('reportsBody').innerHTML = REPORTS.length
  ? REPORTS.map((r, i) => `
      <tr style="animation-delay:${i*.05}s">
        <td><div class="rep-name"><span class="rep-ico"><i class="fa-solid ${r.icon}"></i></span>${r.name}</div></td>
        <td><span class="type-chip ${r.type}">${r.type}</span></td>
        <td>${r.date}</td>
        <td class="mono">${r.size}</td>
        <td class="right"><button class="dl-btn" data-name="${r.name}"><i class="fa-solid fa-download"></i> Download</button></td>
      </tr>`).join('')
  : `<tr><td colspan="5" style="text-align:center;padding:40px;color:var(--muted)">No reports generated yet — click "Generate Report" to create one</td></tr>`;

document.querySelectorAll('.dl-btn').forEach(b => {
  b.addEventListener('click', () => showToast(`Downloading "${b.dataset.name}"`));
});

// ===== Toast =====
const toast = document.getElementById('toast');
function showToast(msg){
  toast.querySelector('span').textContent = msg;
  toast.classList.add('show');
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.remove('show'), 1800);
}
document.querySelectorAll('.chip-btn').forEach(b => {
  b.addEventListener('click', () => showToast(b.textContent.trim() + ' opened'));
});

// ===== Generate Report (real PDF from backend) =====
const overlay = document.getElementById('genOverlay');
const genBar = document.getElementById('genBar');
const genStep = document.getElementById('genStep');

// In-memory list of generated reports (this session)
const GENERATED = [];

function renderRecentReports() {
  const body = document.getElementById('reportsBody');
  if (!body) return;
  body.innerHTML = GENERATED.length
    ? GENERATED.map((r, i) => `
        <tr style="animation-delay:${i*.05}s">
          <td><div class="rep-name"><span class="rep-ico"><i class="fa-solid ${r.icon}"></i></span>${r.name}</div></td>
          <td><span class="type-chip ${r.type}">${r.type}</span></td>
          <td>${r.date}</td>
          <td class="mono">${r.size}</td>
          <td class="right"><button class="dl-btn" data-fmt="${r.fmt}"><i class="fa-solid fa-download"></i> Re-download</button></td>
        </tr>`).join('')
    : `<tr><td colspan="5" style="text-align:center;padding:40px;color:var(--muted)">No reports generated yet — click "Generate Report" to create one</td></tr>`;
  body.querySelectorAll('.dl-btn').forEach(b => {
    b.addEventListener('click', () => doExport(b.dataset.fmt));
  });
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
  return (bytes/(1024*1024)).toFixed(2) + ' MB';
}

async function doExport(fmt) {
  if (!window.AisecAPI) return;
  if (fmt === 'pdf') {
    overlay.classList.add('show');
    genBar.style.width = '0%';
    const stages = [
      { t:'Collecting incident data...',    p:25 },
      { t:'Aggregating threat analytics...', p:50 },
      { t:'Requesting PDF from backend...', p:75 },
    ];
    let i = 0;
    const advance = () => {
      if (i < stages.length) {
        genStep.textContent = stages[i].t;
        genBar.style.width = stages[i].p + '%';
        i++;
        setTimeout(advance, 400);
      }
    };
    advance();
  }

  try {
    const { name, size } = await AisecAPI.downloadReport(fmt);
    if (fmt === 'pdf') {
      genStep.textContent = 'Report ready ✓';
      genBar.style.width = '100%';
      setTimeout(() => overlay.classList.remove('show'), 700);
    }
    GENERATED.unshift({
      name,
      type: fmt === 'pdf' ? 'detailed' : 'executive',
      date: new Date().toLocaleString(),
      size: formatSize(size),
      icon: fmt === 'pdf' ? 'fa-file-pdf' : 'fa-file-csv',
      fmt
    });
    renderRecentReports();
    showToast(`${fmt.toUpperCase()} downloaded: ${name}`);
  } catch (err) {
    if (fmt === 'pdf') overlay.classList.remove('show');
    showToast(err.status === 401 ? 'Session expired — please log in again' : 'Export failed: ' + err.message);
  }
}

document.getElementById('genReport').addEventListener('click', () => doExport('pdf'));
const csvBtn = document.getElementById('genCsv');
if (csvBtn) csvBtn.addEventListener('click', () => doExport('csv'));

// ===== Backend integration =====
async function loadReportsFromBackend(){
  if (!window.AisecAPI) return;
  try {
    const sum = await AisecAPI.reportSummary();
    const a = sum.alerts || {};
    // Override KPI values with REAL data
    const kpis = document.querySelectorAll('.kpi-val');
    if (kpis[0]) { kpis[0].dataset.target = a.total || 0; kpis[0].textContent = a.total || 0; }
    const blockRate = a.total ? ((a.resolved || 0) / a.total * 100).toFixed(1) : '0.0';
    const blockSpan = kpis[1]?.querySelector('span'); if (blockSpan) blockSpan.textContent = blockRate;
    if (kpis[3]) { kpis[3].dataset.target = a.active || 0; kpis[3].textContent = a.active || 0; }

    // Update donut center "Threats" total
    const dNum = document.querySelector('.donut-center .d-num');
    if (dNum) dNum.textContent = (a.total || 0).toLocaleString();

    // Threat distribution from /api/alerts/breakdown
    try {
      const breakdown = await AisecAPI.alertBreakdown();
      const palette = ['#ff6b6b','#ffa94d','#ffd43b','#51cf66','#22b8cf','#9775fa','#fa7268'];
      const entries = Array.isArray(breakdown)
        ? breakdown.map(item => [item?.type ?? 'Unknown', Number(item?.count) || 0])
        : Object.entries(breakdown).map(([label, value]) => [label, Number(value) || 0]);
      const total = entries.reduce((sum, [,count]) => sum + count, 0);
      const sorted = entries.sort((a,b) => b[1] - a[1]);
      const dist = sorted.length
        ? sorted.map(([label, count], i) => ({
            label,
            pct: total ? Math.round(count * 100 / total) : 0,
            color: palette[i % palette.length]
          }))
        : [{ label:'No data', pct:100, color:'#334155' }];
      // Update the donut chart
      const chart = Chart.getChart('distChart');
      if (chart) {
        chart.data.labels = dist.map(d=>d.label);
        chart.data.datasets[0].data = dist.map(d=>d.pct);
        chart.data.datasets[0].backgroundColor = dist.map(d=>d.color);
        chart.update();
      }
      // Update legend
      const legend = document.getElementById('distLegend');
      if (legend) legend.innerHTML = dist.map(d => `
        <li><span class="swatch" style="background:${d.color}"></span><span>${d.label}</span><span class="pct">${d.pct}%</span></li>
      `).join('');
    } catch (err) { /* breakdown is optional */ }

    // Pulse a small badge for live status
    let pill = document.getElementById('reportsLive');
    if (!pill) {
      pill = document.createElement('div');
      pill.id = 'reportsLive';
      pill.style.cssText = 'display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.4);color:#bbf7d0;font-size:11px;font-weight:600;margin-left:10px';
      pill.innerHTML = '<span style="width:6px;height:6px;border-radius:50%;background:#22c55e;box-shadow:0 0 6px #22c55e"></span> LIVE';
      document.querySelector('.inc-title h1')?.appendChild(pill);
    }
  } catch (err) {
    console.warn('Reports backend load failed:', err.message);
  }
}

(function initReports(){
  if (!window.AisecAPI || !AisecAPI.requireAuth()) return;
  loadReportsFromBackend();

  // Debounced live refresh
  let t = null;
  const reload = () => { clearTimeout(t); t = setTimeout(loadReportsFromBackend, 500); };

  try {
    AisecAPI.connectAlertsWS({
      onMessage: (msg) => {
        if (!msg) return;
        if (msg.type === 'alert' || msg.type === 'scan_complete') reload();
      }
    });
  } catch {}
})();
