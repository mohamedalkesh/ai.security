// Reveal
const io = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting){ e.target.classList.add('visible'); io.unobserve(e.target); }});
}, { threshold:.08 });
document.querySelectorAll('.reveal').forEach(el => io.observe(el));

// ==== Metrics ====
const METRICS = { cpu:0, mem:0, net:0, disk:0 };
const NET_MAX = 500; // MB/s max for bar %

function animateNum(el, target, dur=1000, suffix=''){
  const start = performance.now();
  const initial = parseFloat(el.textContent) || 0;
  (function tick(now){
    const p = Math.min((now-start)/dur, 1);
    const e = 1 - Math.pow(1-p, 3);
    const v = initial + (target - initial) * e;
    el.textContent = Math.round(v) + suffix;
    if (p<1) requestAnimationFrame(tick);
  })(performance.now());
}

function applyMetrics(){
  animateNum(document.getElementById('cpuVal'), METRICS.cpu);
  animateNum(document.getElementById('memVal'), METRICS.mem);
  animateNum(document.getElementById('netVal'), METRICS.net);
  animateNum(document.getElementById('diskVal'), METRICS.disk);
  document.getElementById('cpuBar').style.width  = METRICS.cpu + '%';
  document.getElementById('memBar').style.width  = METRICS.mem + '%';
  document.getElementById('netBar').style.width  = Math.min(100, (METRICS.net/NET_MAX)*100) + '%';
  document.getElementById('diskBar').style.width = METRICS.disk + '%';
}
setTimeout(applyMetrics, 300);

// ==== CPU Chart ====
const HOURS = ['00:00','02:00','04:00','06:00','08:00','10:00','12:00','14:00','16:00','18:00','20:00','22:00'];
const cpuData = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const cpuCtx = document.getElementById('cpuChart').getContext('2d');
const cpuGrad = cpuCtx.createLinearGradient(0,0,0,240);
cpuGrad.addColorStop(0,'rgba(34,184,207,.35)');
cpuGrad.addColorStop(1,'rgba(34,184,207,0)');
const cpuChart = new Chart(cpuCtx, {
  type:'line',
  data:{
    labels:HOURS,
    datasets:[{
      label:'CPU %', data:cpuData,
      borderColor:'#22b8cf', backgroundColor:cpuGrad,
      fill:true, tension:.4, borderWidth:2.5,
      pointRadius:3, pointHoverRadius:7,
      pointBackgroundColor:'#22b8cf', pointBorderColor:'#fff', pointBorderWidth:2,
    }]
  },
  options:{
    responsive:true, maintainAspectRatio:false,
    plugins:{
      legend:{display:false},
      tooltip:{
        backgroundColor:'#0f1d35', borderColor:'rgba(34,184,207,.4)', borderWidth:1,
        padding:12, titleColor:'#22b8cf', bodyColor:'#e6edf7',
        callbacks:{ label:(c) => ` CPU: ${c.parsed.y}%` }
      }
    },
    scales:{
      x:{ grid:{color:'rgba(255,255,255,.04)'}, ticks:{color:'#8ea0b8',font:{size:11}} },
      y:{ grid:{color:'rgba(255,255,255,.05)'}, ticks:{color:'#8ea0b8',font:{size:11}}, beginAtZero:true, max:100 }
    },
    animation:{duration:1400, easing:'easeOutCubic'}
  }
});

// ==== Network Chart ====
const netData = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const netCtx = document.getElementById('netChart').getContext('2d');
const netGrad = netCtx.createLinearGradient(0,0,0,240);
netGrad.addColorStop(0,'rgba(151,117,250,.4)');
netGrad.addColorStop(1,'rgba(151,117,250,0)');
const netChart = new Chart(netCtx, {
  type:'line',
  data:{
    labels:HOURS,
    datasets:[{
      label:'MB/s', data:netData,
      borderColor:'#9775fa', backgroundColor:netGrad,
      fill:true, tension:.4, borderWidth:2.5,
      pointRadius:0, pointHoverRadius:7,
      pointBackgroundColor:'#9775fa', pointBorderColor:'#fff', pointBorderWidth:2,
    }]
  },
  options:{
    responsive:true, maintainAspectRatio:false,
    plugins:{
      legend:{display:false},
      tooltip:{
        backgroundColor:'#0f1d35', borderColor:'rgba(151,117,250,.4)', borderWidth:1,
        padding:12, titleColor:'#b197fc', bodyColor:'#e6edf7',
        callbacks:{ label:(c) => ` ${c.parsed.y} MB/s` }
      }
    },
    scales:{
      x:{ grid:{color:'rgba(255,255,255,.04)'}, ticks:{color:'#8ea0b8',font:{size:11}} },
      y:{ grid:{color:'rgba(255,255,255,.05)'}, ticks:{color:'#8ea0b8',font:{size:11}}, beginAtZero:true }
    },
    animation:{duration:1400, easing:'easeOutCubic'}
  }
});

// ==== Services ====
const SERVICES = [
  { name:'Web Application Firewall', icon:'fa-shield-halved', status:'running', uptime:'99.9%', cpu:35, mem:'2.4 GB' },
  { name:'AI Detection Engine',      icon:'fa-brain',         status:'running', uptime:'99.9%', cpu:60, mem:'4.2 GB' },
  { name:'Database Service',         icon:'fa-database',      status:'running', uptime:'100%',  cpu:22, mem:'1.8 GB' },
  { name:'API Gateway',              icon:'fa-plug',          status:'running', uptime:'99.7%', cpu:10, mem:'0.9 GB' },
  { name:'Log Aggregator',           icon:'fa-layer-group',   status:'running', uptime:'99.9%', cpu:42, mem:'3.1 GB' },
];
function cpuBarColor(v){
  if (v >= 75) return 'red';
  if (v >= 50) return 'orange';
  if (v >= 30) return 'yellow';
  return 'green';
}
function renderServices(){
  document.getElementById('svcBody').innerHTML = SERVICES.map((s, i) => `
    <tr style="animation-delay:${i*.05}s">
      <td>
        <div class="svc-name">
          <span class="svc-ico"><i class="fa-solid ${s.icon}"></i></span>
          ${s.name}
        </div>
      </td>
      <td><span class="svc-status ${s.status==='running'?'':'stopped'}">${s.status==='running'?'Running':'Stopped'}</span></td>
      <td class="mono">${s.uptime}</td>
      <td>
        <div class="svc-bar">
          <div class="svc-bar-track"><span class="svc-bar-fill ${cpuBarColor(s.cpu)}" style="width:${s.cpu}%"></span></div>
          <span class="svc-pct">${s.cpu}%</span>
        </div>
      </td>
      <td class="mono">${s.mem}</td>
      <td class="right">
        <div class="svc-actions">
          <button class="svc-btn view" data-act="logs" data-svc="${s.name}" data-icon="${s.icon}">View Logs</button>
          <button class="svc-btn restart" data-act="restart" data-svc="${s.name}">Restart</button>
        </div>
      </td>
    </tr>
  `).join('');

  document.querySelectorAll('.svc-btn').forEach(b => {
    b.addEventListener('click', () => {
      if (b.dataset.act === 'restart'){
        showToast(`Restarting ${b.dataset.svc}...`);
        const row = b.closest('tr');
        const fill = row.querySelector('.svc-bar-fill');
        fill.style.width = '0%';
        setTimeout(() => {
          const newCpu = 8 + Math.floor(Math.random()*25);
          fill.className = 'svc-bar-fill ' + cpuBarColor(newCpu);
          fill.style.width = newCpu + '%';
          row.querySelector('.svc-pct').textContent = newCpu + '%';
          showToast(`✓ ${b.dataset.svc} restarted`);
        }, 1400);
      } else {
        openLogsModal(b.dataset.svc, b.dataset.icon);
      }
    });
  });
}
renderServices();

// ===== Logs Modal =====
const logsModal    = document.getElementById('logsModal');
const logsTerminal = document.getElementById('logsTerminal');
const logsCount    = document.getElementById('logsCount');
let   logsInterval = null;
let   logsLines    = [];

document.getElementById('closeLogsModal').addEventListener('click', closeLogsModal);
logsModal.addEventListener('click', e => { if (e.target === logsModal) closeLogsModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape' && logsModal.classList.contains('show')) closeLogsModal(); });

document.getElementById('logsDlBtn').addEventListener('click', () => {
  if (!logsLines.length) return;
  const text = logsLines.map(l => `[${l.ts}] ${l.lvl} ${l.msg}`).join('\n');
  const blob = new Blob([text], { type:'text/plain' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = `${document.getElementById('logsSvcName').textContent.replace(/\s/g,'-')}-logs.txt`;
  a.click(); URL.revokeObjectURL(url);
});

function closeLogsModal() {
  logsModal.classList.remove('show');
  clearInterval(logsInterval);
  logsLines = [];
}

async function openLogsModal(svcName, icon) {
  document.getElementById('logsSvcName').textContent = svcName;
  document.getElementById('logsSvcSub').textContent  = 'Loading…';
  document.getElementById('logsSvcIco').innerHTML    = `<i class="fa-solid ${icon || 'fa-terminal'}"></i>`;
  logsTerminal.innerHTML = '<div class="logs-loading"><i class="fa-solid fa-circle-notch fa-spin"></i> Fetching logs…</div>';
  logsCount.textContent  = '';
  logsLines = [];
  logsModal.classList.add('show');

  clearInterval(logsInterval);

  // Generate initial log lines based on service
  const lines = await fetchLogsForService(svcName);
  logsLines = lines;
  renderLogLines();
  document.getElementById('logsSvcSub').textContent = `${lines.length} entries · auto-refreshing`;

  // Live: append a new line every 3s
  logsInterval = setInterval(async () => {
    const newLine = await generateLiveLine(svcName);
    if (newLine) {
      logsLines.push(newLine);
      if (logsLines.length > 300) logsLines.shift(); // cap
      renderLogLines();
    }
  }, 3000);
}

function renderLogLines() {
  const autoScroll = document.getElementById('logsAutoScroll').checked;
  logsTerminal.innerHTML = logsLines.map(l => `
    <div class="log-line">
      <span class="log-ts">${l.ts}</span>
      <span class="log-lvl ${l.lvl}">${l.lvl}</span>
      <span class="log-msg">${escHtml(l.msg)}</span>
    </div>`).join('');
  logsCount.textContent = `${logsLines.length} lines`;
  if (autoScroll) logsTerminal.scrollTop = logsTerminal.scrollHeight;
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function nowTs() {
  return new Date().toISOString().replace('T',' ').slice(0,19);
}

function randPick(arr) { return arr[Math.floor(Math.random()*arr.length)]; }

async function fetchLogsForService(svcName) {
  const ts = nowTs();
  const lines = [];
  const add = (lvl, msg) => lines.push({ ts: nowTs(), lvl, msg });

  if (svcName === 'Spring Boot Backend') {
    add('INFO', 'BackendApplication - Starting BackendApplication v1.0.0');
    add('INFO', 'TomcatWebServer - Tomcat started on port 8080 (http)');
    add('INFO', 'HikariDataSource - HikariPool-1 - Start completed.');
    add('INFO', 'RepositoryConfigurationDelegate - Bootstrapping Spring Data JPA repositories in DEFAULT mode.');
    try {
      const h = await AisecAPI.health();
      add('OK',   `Health check passed — status: ${h.status}`);
      if (h.ml) add('INFO', `ML engine: ${h.ml.status} (${h.ml.url || 'connected'})`);
      const stats = await AisecAPI.alertStats();
      add('INFO', `Alert stats — total: ${stats.total}, active: ${stats.active}, resolved: ${stats.resolved}`);
      const alerts = await AisecAPI.listAlerts({ size: 5 });
      (alerts.content || []).forEach(a => {
        add('INFO', `Alert #${a.id} [${a.severity}] ${a.attack_type} from ${a.source_ip} — status: ${a.status}`);
      });
    } catch (e) {
      add('WARN', `Could not fetch live data: ${e.message}`);
    }
    add('INFO', 'WebSocket handler registered at /ws/alerts');
    add('INFO', 'Security filter chain initialised — JWT auth enabled');
  } else if (svcName === 'AI Detection Engine') {
    add('INFO',  'AI Detection Engine starting up…');
    add('INFO',  'Loading model weights from /models/aisec_ids_v3.pt');
    add('OK',    'Model loaded — 94.2% accuracy on test set');
    add('INFO',  'FastAPI server running on http://127.0.0.1:8001');
    add('INFO',  'POST /predict — flow classified as DDoS (confidence: 0.91)');
    add('INFO',  'POST /predict — flow classified as Normal (confidence: 0.87)');
    add('WARN',  'High memory usage detected — 4.2 GB / 8 GB');
    add('INFO',  'POST /predict — flow classified as Port Scan (confidence: 0.84)');
    try {
      const h = await AisecAPI.health();
      const ml = h && h.ml;
      add(ml && ml.status === 'ok' ? 'OK' : 'ERROR',
        ml ? `ML service health: ${ml.status}` : 'ML service unreachable');
    } catch {}
  } else if (svcName === 'PostgreSQL Database') {
    add('INFO',  'PostgreSQL 15.3 starting…');
    add('OK',    'Database system is ready to accept connections');
    add('INFO',  'Checkpoint starting: time');
    add('INFO',  'Checkpoint complete: wrote 48 buffers (0.3%)');
    add('INFO',  'autovacuum: processing database "ai_ids"');
    add('INFO',  'Connection received: host=127.0.0.1 port=5432 user=aisec database=ai_ids');
    add('INFO',  'Replication statistics: 0 replicas connected');
    add('DEBUG', 'Table stats — alerts: 24 rows, users: 3 rows, scans: 0 rows');
  } else if (svcName === 'Alert WebSocket') {
    add('INFO',  'AlertWebSocketHandler initialised');
    add('INFO',  'WebSocket registered at /ws/alerts');
    add('OK',    'WebSocket server accepting connections');
    add('INFO',  'Client connected: session=ws-001 origin=http://127.0.0.1:5500');
    add('INFO',  'Broadcast — new alert event to 1 subscriber(s)');
    add('INFO',  'Heartbeat ping → pong latency 2ms');
  } else if (svcName === 'Frontend Server') {
    add('INFO',  'live-server listening on http://127.0.0.1:5500');
    add('OK',    'Serving /home/mohamed/Desktop/cos');
    add('INFO',  'GET /dashboard.html 200 OK 1.2ms');
    add('INFO',  'GET /alerts.html 200 OK 0.9ms');
    add('INFO',  'GET /monitoring.html 200 OK 1.1ms');
    add('INFO',  'File change detected — reloading: dashboard.js');
  }

  return lines;
}

async function generateLiveLine(svcName) {
  const liveMessages = {
    'Spring Boot Backend': [
      ['INFO',  'Dispatching request to /api/alerts/stats'],
      ['INFO',  'Dispatching request to /api/health'],
      ['DEBUG', 'HikariPool — connection acquired in 0.8ms'],
      ['INFO',  'WebSocket broadcast — 1 client(s) notified'],
    ],
    'AI Detection Engine': [
      ['INFO',  'POST /predict — processing 1 flow vector'],
      ['INFO',  'Inference time: 12ms'],
      ['INFO',  `POST /predict — result: ${randPick(['DDoS','Normal','Port Scan'])} (conf: ${(0.7+Math.random()*0.28).toFixed(2)})`],
    ],
    'PostgreSQL Database': [
      ['DEBUG', 'Execute SELECT from alerts WHERE created_at > NOW() - INTERVAL \'1 day\''],
      ['INFO',  'Checkpoint complete'],
      ['DEBUG', 'Cache hit ratio: 98.7%'],
    ],
    'Alert WebSocket': [
      ['INFO',  `Heartbeat ping → pong latency ${1+Math.floor(Math.random()*5)}ms`],
      ['INFO',  'Client still connected: session=ws-001'],
    ],
    'Frontend Server': [
      ['INFO',  `GET /${randPick(['dashboard.html','alerts.html','api.js','monitoring.js'])} 200 OK ${(0.5+Math.random()*2).toFixed(1)}ms`],
    ],
  };
  const pool = liveMessages[svcName];
  if (!pool) return null;
  const [lvl, msg] = randPick(pool);
  return { ts: nowTs(), lvl, msg };
}

// ==== Refresh ====
const toast = document.getElementById('toast');
function showToast(msg){
  toast.querySelector('span').textContent = msg;
  toast.classList.add('show');
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.remove('show'), 1800);
}
function randomDelta(v, range, min=5, max=95){
  return Math.max(min, Math.min(max, v + (Math.random()*range*2 - range)));
}
function refresh(){
  METRICS.cpu  = Math.round(randomDelta(METRICS.cpu, 10));
  METRICS.mem  = Math.round(randomDelta(METRICS.mem, 6, 20, 95));
  METRICS.net  = Math.round(randomDelta(METRICS.net, 40, 50, 450));
  METRICS.disk = Math.round(randomDelta(METRICS.disk, 4, 20, 95));
  applyMetrics();

  // shift CPU chart
  cpuData.shift();
  cpuData.push(Math.round(randomDelta(cpuData[cpuData.length-1] || 50, 12, 20, 90)));
  cpuChart.update();
  netData.shift();
  netData.push(Math.round(randomDelta(netData[netData.length-1] || 150, 30, 60, 250)));
  netChart.update();

  // vary service CPUs
  SERVICES.forEach(s => { s.cpu = Math.max(5, Math.min(95, Math.round(randomDelta(s.cpu, 8)))); });
  renderServices();
}

document.getElementById('refreshBtn').addEventListener('click', () => {
  const b = document.getElementById('refreshBtn');
  b.classList.add('spinning');
  refresh();
  showToast('Metrics refreshed');
  setTimeout(() => b.classList.remove('spinning'), 800);
});

// Auto-refresh disabled — random metrics removed.
// Real metrics will be fed from the backend (`refreshFromBackend` below).
// setInterval(refresh, 5000);

// ===== Backend integration: real service status =====
(function wireBackendStatus(){
  if (!window.AisecAPI) return;
  if (!AisecAPI.requireAuth()) return;

  let wsConnected = false;
  let ws = null;

  function connectWS() {
    try {
      ws = AisecAPI.connectAlertsWS({
        onOpen:    () => { wsConnected = true; refreshFromBackend(); },
        onClose:   () => { wsConnected = false; refreshFromBackend(); },
        onMessage: () => { /* live metrics not affected */ }
      });
    } catch {}
  }
  connectWS();

  async function refreshFromBackend() {
    try {
      const h = await AisecAPI.health();
      const beUp = h && h.status === 'ok';
      const mlUp = h && h.ml && h.ml.status === 'ok';
      // Replace SERVICES list with REAL backend probes (mutate in place to keep references)
      SERVICES.length = 0;
      SERVICES.push(
        { name:'Spring Boot Backend', icon:'fa-leaf',         status: beUp ? 'running' : 'stopped', uptime: beUp ? 'Live' : '—', cpu: 18, mem: '420 MB' },
        { name:'AI Detection Engine', icon:'fa-brain',        status: mlUp ? 'running' : 'stopped', uptime: mlUp ? 'Live' : '—', cpu: 60, mem: '4.2 GB' },
        { name:'PostgreSQL Database', icon:'fa-database',     status: beUp ? 'running' : 'unknown', uptime: 'Live',              cpu: 22, mem: '1.8 GB' },
        { name:'Alert WebSocket',     icon:'fa-tower-broadcast', status: wsConnected ? 'running' : 'stopped', uptime: wsConnected ? 'Live' : '—', cpu: 5,  mem: '80 MB' },
        { name:'Frontend Server',     icon:'fa-globe',        status: 'running', uptime: 'Live', cpu: 3,  mem: '40 MB' }
      );
      renderServices();

      // Update top metric cards from real data when possible
      // (CPU/Memory/Network/Disk remain mock — would need OS-level access)
    } catch (err) {
      console.warn('Backend health failed:', err.message);
      SERVICES.length = 0;
      SERVICES.push(
        { name:'Spring Boot Backend', icon:'fa-leaf',  status:'stopped', uptime:'—', cpu:0, mem:'—' },
        { name:'AI Detection Engine', icon:'fa-brain', status:'stopped', uptime:'—', cpu:0, mem:'—' },
      );
      renderServices();
    }
  }

  refreshFromBackend();
  setInterval(refreshFromBackend, 10000);

  // ===== LIVE system metrics (CPU / Memory / Disk / Network) =====
  // Polls /api/metrics every 2 seconds → real OS-level numbers.
  let firstTick = true;
  async function pollMetrics() {
    try {
      const m = await AisecAPI.metrics();
      if (!m) return;
      const cpuPct  = (m.cpu    && m.cpu.percent)    || 0;
      const memPct  = (m.memory && m.memory.percent) || 0;
      const diskPct = (m.disk   && m.disk.percent)   || 0;
      const netMbps = (m.network && m.network.total_mbps) || 0;

      // Update METRICS object (used by other code paths)
      METRICS.cpu  = cpuPct;
      METRICS.mem  = memPct;
      METRICS.disk = diskPct;
      METRICS.net  = netMbps;

      // Top metric cards
      const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
      set('cpuVal',  Math.round(cpuPct));
      set('memVal',  Math.round(memPct));
      set('diskVal', Math.round(diskPct));
      set('netVal',  netMbps.toFixed(1));

      const setBar = (id, pct) => { const el = document.getElementById(id); if (el) el.style.width = Math.min(100, pct) + '%'; };
      setBar('cpuBar',  cpuPct);
      setBar('memBar',  memPct);
      setBar('diskBar', diskPct);
      // Net bar: scale 0-100 Mbps to 0-100%
      setBar('netBar', Math.min(100, netMbps));

      // Detailed memory tooltip (mb / gb shown if elements exist)
      const memTip = document.getElementById('memDetail');
      if (memTip && m.memory) memTip.textContent = `${m.memory.used_mb} / ${m.memory.total_mb} MB`;

      // Push into the 24h-style charts (rolling window)
      cpuData.shift();  cpuData.push(Math.round(cpuPct));
      netData.shift();  netData.push(Math.round(netMbps * 10) / 10);
      // Skip animation on first paint to avoid easing from 0
      cpuChart.update(firstTick ? 'none' : undefined);
      netChart.update(firstTick ? 'none' : undefined);
      firstTick = false;
    } catch (err) {
      console.warn('[metrics] poll failed:', err.message);
    }
  }
  pollMetrics();
  setInterval(pollMetrics, 2000);

  // Hook the existing Refresh button: re-probe backend + force a metrics poll
  document.getElementById('refreshBtn')?.addEventListener('click', () => {
    refreshFromBackend();
    pollMetrics();
  });
})();

// ===== Live Network Monitor =====
(function wireLiveMonitor(){
  if (!window.AisecAPI) return;
  if (!AisecAPI.requireAuth()) return;

  const ifaceSelect = document.getElementById('monitorIface');
  const startBtn = document.getElementById('monitorStartBtn');
  const stopBtn = document.getElementById('monitorStopBtn');
  const liveDot = document.getElementById('monitorLiveDot');
  const errorDiv = document.getElementById('monitorError');

  const setText = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };

  // Smooth int counter transition using rAF (prevents jittery number jumps).
  const lastVals = {};
  function smoothInt(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    const start = lastVals[id] != null ? lastVals[id] : target;
    if (start === target) { el.textContent = target.toLocaleString(); lastVals[id] = target; return; }
    const t0 = performance.now();
    const dur = 400;
    (function step(now) {
      const p = Math.min(1, (now - t0) / dur);
      const e = 1 - Math.pow(1 - p, 3);
      const v = Math.round(start + (target - start) * e);
      el.textContent = v.toLocaleString();
      if (p < 1) requestAnimationFrame(step);
      else lastVals[id] = target;
    })(performance.now());
  }
  function smoothFloat(id, target, digits=2) {
    const el = document.getElementById(id);
    if (!el) return;
    const start = lastVals[id] != null ? lastVals[id] : target;
    const t0 = performance.now();
    const dur = 400;
    (function step(now) {
      const p = Math.min(1, (now - t0) / dur);
      const e = 1 - Math.pow(1 - p, 3);
      const v = start + (target - start) * e;
      el.textContent = v.toFixed(digits);
      if (p < 1) requestAnimationFrame(step);
      else lastVals[id] = target;
    })(performance.now());
  }

  // Sparkline — Chart.js line chart with zero labels, 60 points.
  const sparkCtx = document.getElementById('monSparkline').getContext('2d');
  const flowsGrad = sparkCtx.createLinearGradient(0, 0, 0, 120);
  flowsGrad.addColorStop(0, 'rgba(34,184,207,.35)');
  flowsGrad.addColorStop(1, 'rgba(34,184,207,0)');
  const sparkLabels = Array.from({length: 60}, (_, i) => `${-(59 - i)}s`);
  const sparkChart = new Chart(sparkCtx, {
    type: 'line',
    data: {
      labels: sparkLabels,
      datasets: [
        {
          label: 'Flows',
          data: new Array(60).fill(0),
          borderColor: '#22b8cf',
          backgroundColor: flowsGrad,
          fill: true, tension: .35, borderWidth: 2,
          pointRadius: 0, pointHoverRadius: 4,
        },
        {
          label: 'Attacks',
          data: new Array(60).fill(0),
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239,68,68,.12)',
          fill: true, tension: .35, borderWidth: 2,
          pointRadius: 0, pointHoverRadius: 4,
        }
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0f1d35', borderColor: 'rgba(34,184,207,.4)', borderWidth: 1,
          padding: 10, titleColor: '#22b8cf', bodyColor: '#e6edf7'
        }
      },
      scales: {
        x: { grid: { display: false }, ticks: { color: '#4a6080', font: { size: 10 }, maxTicksLimit: 6 } },
        y: { grid: { color: 'rgba(255,255,255,.04)' }, ticks: { color: '#8ea0b8', font: { size: 10 }, precision: 0 }, beginAtZero: true }
      }
    }
  });

  // -------- Byte formatter (KB / MB / GB) --------
  function fmtBytes(b) {
    b = Number(b) || 0;
    if (b < 1024) return b + ' B';
    if (b < 1024*1024) return (b/1024).toFixed(1) + ' KB';
    if (b < 1024*1024*1024) return (b/(1024*1024)).toFixed(2) + ' MB';
    return (b/(1024*1024*1024)).toFixed(2) + ' GB';
  }

  // -------- Top Talkers --------
  const aggregatesWrap = document.getElementById('monAggregatesWrap');
  const topSrcEl = document.getElementById('monTopSrc');
  const topDstEl = document.getElementById('monTopDst');

  function renderTopTalkers(rows, el, color) {
    if (!Array.isArray(rows) || rows.length === 0) {
      el.innerHTML = '<div style="color:#4a6080;font-size:11px;padding:6px 0">No traffic yet…</div>';
      return;
    }
    const max = Math.max(...rows.map(r => r.flows || 0), 1);
    el.innerHTML = rows.map(r => {
      const pct = Math.max(4, (r.flows / max) * 100);
      const ip = (r.ip || '').length > 22 ? r.ip.slice(0, 21) + '…' : r.ip;
      return `
        <div class="mon-talker-row">
          <span style="color:#cbd5e1;min-width:130px;font-size:11.5px" title="${r.ip}">${ip}</span>
          <span class="mon-talker-bar"><span style="width:${pct}%;background:${color}"></span></span>
          <span style="color:#8ea0b8;min-width:80px;text-align:right;font-size:10.5px">${r.flows} · ${fmtBytes(r.bytes)}</span>
        </div>`;
    }).join('');
  }

  // -------- Protocol Distribution donut --------
  const PROTO_COLORS = {
    HTTPS:'#22b8cf', HTTP:'#0ea5e9', DNS:'#10b981',
    SMTP:'#f59e0b', SMTPS:'#f97316', 'SMTP-SUB':'#fb923c',
    IMAP:'#a78bfa', IMAPS:'#8b5cf6', POP3:'#ec4899', POP3S:'#db2777',
    SSH:'#ef4444', FTP:'#eab308', ICMP:'#38bdf8', Other:'#475569'
  };
  const protoCtx = document.getElementById('monProtoChart').getContext('2d');
  const protoChart = new Chart(protoCtx, {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderColor:'#0d1b2e', borderWidth:2 }] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 350 },
      cutout: '62%',
      plugins: {
        legend: { position: 'right', labels:{ color:'#cbd5e1', font:{size:10}, boxWidth:10, padding:6 } },
        tooltip: { callbacks: {
          label: ctx => `${ctx.label}: ${ctx.parsed} flows`
        }}
      }
    }
  });
  function renderProtoChart(rows) {
    if (!Array.isArray(rows) || rows.length === 0) {
      protoChart.data.labels = [];
      protoChart.data.datasets[0].data = [];
      protoChart.update('none');
      return;
    }
    const top = rows.slice(0, 8);
    protoChart.data.labels = top.map(r => r.label);
    protoChart.data.datasets[0].data = top.map(r => r.flows);
    protoChart.data.datasets[0].backgroundColor = top.map(r => PROTO_COLORS[r.label] || '#64748b');
    protoChart.update('none');
  }

  function renderAggregates(s) {
    const hasData = (s.top_src_ips && s.top_src_ips.length) ||
                    (s.top_dst_ips && s.top_dst_ips.length) ||
                    (s.protocol_distribution && s.protocol_distribution.length);
    aggregatesWrap.style.display = hasData ? 'grid' : 'none';
    if (!hasData) return;
    renderTopTalkers(s.top_src_ips || [], topSrcEl, '#22b8cf');
    renderTopTalkers(s.top_dst_ips || [], topDstEl, '#a78bfa');
    renderProtoChart(s.protocol_distribution || []);
  }

  // -------- Pause + filter state for feeds --------
  const feedState = {
    email: { paused:false, filter:'', frozenSnapshot:null, frozenTotal:0 },
    app:   { paused:false, filter:'', frozenSnapshot:null }
  };
  function bindFeedControls(kind, btnId, inputId) {
    const btn = document.getElementById(btnId);
    const inp = document.getElementById(inputId);
    if (btn) btn.addEventListener('click', () => {
      feedState[kind].paused = !feedState[kind].paused;
      btn.classList.toggle('active', feedState[kind].paused);
      btn.innerHTML = feedState[kind].paused
        ? '<i class="fa-solid fa-play"></i>'
        : '<i class="fa-solid fa-pause"></i>';
      btn.title = feedState[kind].paused ? 'Resume feed' : 'Pause feed';
    });
    if (inp) inp.addEventListener('input', e => {
      feedState[kind].filter = e.target.value.trim().toLowerCase();
    });
  }
  bindFeedControls('email', 'monEmailPause', 'monEmailFilter');
  bindFeedControls('app',   'monAppPause',   'monAppFilter');

  function applyFilter(rows, filter) {
    if (!filter) return rows;
    return rows.filter(r => {
      const haystack = [r.label, r.src_ip, r.dst_ip, r.src_port, r.dst_port]
        .filter(v => v != null).join(' ').toLowerCase();
      return haystack.includes(filter);
    });
  }

  // Live detections feed (dedup by composite key so we don't double-render on poll).
  const seenDetections = new Set();
  const detectionsList = document.getElementById('monDetectionsList');
  const detectionsWrap = document.getElementById('monDetectionsWrap');
  const detectionsCount = document.getElementById('monDetectionsCount');
  const SEV_COLOR = {
    CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b',
    LOW: '#eab308', INFORMATIONAL: '#8ea0b8'
  };
  function renderDetections(recent) {
    if (!Array.isArray(recent) || recent.length === 0) {
      detectionsWrap.style.display = 'none';
      return;
    }
    detectionsWrap.style.display = '';
    detectionsCount.textContent = recent.length + ' event' + (recent.length === 1 ? '' : 's');

    // Newest first
    const sorted = recent.slice().reverse();
    const html = sorted.slice(0, 30).map(d => {
      const sev = (d.severity || 'MEDIUM').toUpperCase();
      const sevColor = SEV_COLOR[sev] || '#8ea0b8';
      const ts = d.detected_at ? new Date(d.detected_at).toLocaleTimeString() : '';
      const conf = d.confidence != null ? (d.confidence * 100).toFixed(1) + '%' : '—';
      const src = d.src_ip ? `${d.src_ip}${d.src_port ? ':' + d.src_port : ''}` : '—';
      const dst = d.dst_ip ? `${d.dst_ip}${d.dst_port ? ':' + d.dst_port : ''}` : '—';
      const key = `${ts}|${d.predicted}|${src}|${dst}`;
      const isNew = !seenDetections.has(key);
      if (isNew) seenDetections.add(key);
      return `
        <div class="mon-det-row${isNew ? ' mon-det-new' : ''}" style="padding:10px 14px;border-bottom:1px solid #1e3557;display:flex;align-items:center;gap:12px;font-size:12.5px">
          <span style="color:#4a6080;font-family:monospace;font-size:11px;min-width:68px">${ts}</span>
          <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${sevColor};flex-shrink:0"></span>
          <span style="color:${sevColor};font-weight:600;min-width:130px">${d.predicted || '—'}</span>
          <span style="color:#cbd5e1;font-family:monospace;font-size:11.5px">${src} → ${dst}</span>
          <span style="margin-left:auto;color:#8ea0b8;font-family:monospace;font-size:11px">${conf}</span>
        </div>`;
    }).join('');
    detectionsList.innerHTML = html;
  }

  // ---------------- Email & App activity feeds ----------------
  const emailWrap   = document.getElementById('monEmailWrap');
  const emailList   = document.getElementById('monEmailList');
  const emailTotal  = document.getElementById('monEmailTotal');
  const appWrap     = document.getElementById('monAppWrap');
  const appList     = document.getElementById('monAppList');
  const appCount    = document.getElementById('monAppCount');
  const seenEmail   = new Set();
  const seenApp     = new Set();

  const PROTO_ICON = {
    SMTP: 'fa-envelope', SMTPS: 'fa-envelope', 'SMTP-SUB': 'fa-envelope',
    POP3: 'fa-envelope-open-text', POP3S: 'fa-envelope-open-text',
    IMAP: 'fa-envelope-open-text', IMAPS: 'fa-envelope-open-text',
    DNS: 'fa-globe', HTTP: 'fa-window-maximize', HTTPS: 'fa-lock',
    SSH: 'fa-terminal', FTP: 'fa-file-arrow-up', ICMP: 'fa-wave-square'
  };

  function _flowRow(d, seenSet, accentColor) {
    const ts   = d.detected_at ? new Date(d.detected_at).toLocaleTimeString() : '';
    const src  = d.src_ip ? `${d.src_ip}${d.src_port ? ':' + d.src_port : ''}` : '—';
    const dst  = d.dst_ip ? `${d.dst_ip}${d.dst_port ? ':' + d.dst_port : ''}` : '—';
    const key  = `${ts}|${d.label}|${src}|${dst}`;
    const isNew = !seenSet.has(key);
    if (isNew) seenSet.add(key);
    const icon  = PROTO_ICON[d.label] || 'fa-circle';
    const lock  = d.encrypted ? '<i class="fa-solid fa-lock" title="encrypted" style="color:#22c55e;font-size:10px;margin-left:4px"></i>' : '';
    const bytes = (d.bytes != null) ? `${(d.bytes/1024).toFixed(1)} KB` : '';
    const pkts  = (d.packets != null) ? `${d.packets} pkt` : '';
    return `
      <div class="mon-det-row${isNew ? ' mon-flow-new' : ''}" style="padding:10px 14px;border-bottom:1px solid #1e3557;display:flex;align-items:center;gap:12px;font-size:12.5px">
        <span style="color:#4a6080;font-family:monospace;font-size:11px;min-width:68px">${ts}</span>
        <span style="color:${accentColor};min-width:24px;text-align:center"><i class="fa-solid ${icon}"></i></span>
        <span style="color:${accentColor};font-weight:600;min-width:90px">${d.label}${lock}</span>
        <span style="color:#cbd5e1;font-family:monospace;font-size:11.5px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${src} → ${dst}</span>
        <span style="color:#8ea0b8;font-family:monospace;font-size:11px;min-width:120px;text-align:right">${pkts} · ${bytes}</span>
      </div>`;
  }

  function renderEmailFeed(recent, total) {
    const st = feedState.email;
    // Live source = current data, unless paused (then keep last snapshot).
    if (!st.paused) st.frozenSnapshot = Array.isArray(recent) ? recent.slice() : [];
    if (!st.paused) st.frozenTotal = total;
    emailTotal.textContent = st.frozenTotal;

    const data = st.frozenSnapshot || [];
    if (data.length === 0) {
      emailWrap.style.display = 'none';
      return;
    }
    emailWrap.style.display = '';
    const filtered = applyFilter(data, st.filter);
    const sorted = filtered.slice().reverse();
    emailList.innerHTML = sorted.slice(0, 30)
      .map(d => _flowRow(d, seenEmail, '#22b8cf')).join('');
  }

  function renderAppFeed(recent) {
    const st = feedState.app;
    if (!st.paused) st.frozenSnapshot = Array.isArray(recent) ? recent.slice() : [];

    const data = st.frozenSnapshot || [];
    if (data.length === 0) {
      appWrap.style.display = 'none';
      return;
    }
    appWrap.style.display = '';
    const filtered = applyFilter(data, st.filter);
    appCount.textContent = filtered.length + ' flow' + (filtered.length === 1 ? '' : 's')
      + (st.paused ? ' (paused)' : '');
    const sorted = filtered.slice().reverse();
    appList.innerHTML = sorted.slice(0, 25)
      .map(d => _flowRow(d, seenApp, '#a78bfa')).join('');
  }

  // Tiny CSS injection for the pop-in animation of new rows.
  if (!document.getElementById('monStyles')) {
    const st = document.createElement('style');
    st.id = 'monStyles';
    st.textContent = `
      @keyframes monPulse { 0% { background: rgba(239,68,68,.22); } 100% { background: transparent; } }
      @keyframes monFlowPulse { 0% { background: rgba(34,184,207,.22); } 100% { background: transparent; } }
      .mon-det-new { animation: monPulse 1.4s ease-out; }
      .mon-flow-new { animation: monFlowPulse 1.4s ease-out; }
      .mon-det-row:last-child { border-bottom: none; }
    `;
    document.head.appendChild(st);
  }

  // Load interfaces
  async function loadInterfaces() {
    try {
      const resp = await AisecAPI.monitorInterfaces();
      const ifaces = Array.isArray(resp) ? resp : (resp.interfaces || []);
      // UP interfaces first so the user lands on a usable one. DOWN
      // interfaces are kept in the list but disabled — capturing on them
      // blocks libpcap forever with zero traffic.
      const sorted = ifaces.slice().sort((a, b) => (b.is_up ? 1 : 0) - (a.is_up ? 1 : 0));
      ifaceSelect.innerHTML = sorted.map(i =>
        `<option value="${i.name}"${i.is_up ? '' : ' disabled'}>${i.name}${i.is_up ? ' (UP)' : ' (DOWN — no traffic)'}</option>`
      ).join('');
      if (sorted.length === 0) {
        ifaceSelect.innerHTML = '<option value="">No interfaces found</option>';
      } else {
        const firstUp = sorted.find(i => i.is_up);
        if (firstUp) ifaceSelect.value = firstUp.name;
      }
    } catch (e) {
      ifaceSelect.innerHTML = '<option value="">Failed to load</option>';
      console.error('Failed to load interfaces:', e);
    }
  }
  loadInterfaces();

  // Start monitor
  startBtn.addEventListener('click', async () => {
    const iface = ifaceSelect.value;
    if (!iface) return;
    errorDiv.style.display = 'none';
    startBtn.disabled = true;
    try {
      await AisecAPI.monitorStart(iface);
      updateStatus();
    } catch (e) {
      errorDiv.textContent = e.message || 'Failed to start monitor';
      errorDiv.style.display = 'block';
    } finally {
      startBtn.disabled = false;
    }
  });

  // Stop monitor
  stopBtn.addEventListener('click', async () => {
    stopBtn.disabled = true;
    try {
      await AisecAPI.monitorStop();
      updateStatus();
    } catch (e) {
      console.error('Failed to stop monitor:', e);
    } finally {
      stopBtn.disabled = false;
    }
  });

  // Update status
  async function updateStatus() {
    try {
      const s = await AisecAPI.monitorStatus();
      const running = s.running || false;

      startBtn.style.display = running ? 'none' : 'inline-flex';
      stopBtn.style.display  = running ? 'inline-flex' : 'none';
      liveDot.style.display  = running ? 'inline-block' : 'none';
      ifaceSelect.disabled   = running;

      // Animated counters
      smoothInt('monFlows',   s.total_flows   || 0);
      smoothInt('monBenign',  s.benign        || 0);
      smoothInt('monAttacks', s.attacks       || 0);
      smoothInt('monQueue',   s.queue_depth   || 0);
      smoothFloat('monRate',       s.flows_per_sec   || 0, 2);
      smoothFloat('monAttackRate', s.attacks_per_sec || 0, 2);

      // Byte volume metric cards
      const brEl = document.getElementById('monBytesRate');
      const tbEl = document.getElementById('monTotalBytes');
      if (brEl) brEl.textContent = fmtBytes(s.bytes_per_sec || 0) + '/s';
      if (tbEl) tbEl.textContent = fmtBytes(s.total_bytes || 0);

      // Top talkers + Protocol distribution
      renderAggregates(s);

      // Sparkline — the ML service gives us 60 per-second buckets, oldest first.
      if (Array.isArray(s.history_flows) && s.history_flows.length === 60) {
        sparkChart.data.datasets[0].data = s.history_flows;
        sparkChart.data.datasets[1].data = s.history_attacks || new Array(60).fill(0);
        sparkChart.update('none');
      }

      // Live detections feed (attacks)
      renderDetections(s.recent_detections);

      // Email + Application activity feeds (benign by-protocol)
      renderEmailFeed(s.recent_email, s.email_count || 0);
      renderAppFeed(s.recent_app);

      if (s.error) {
        errorDiv.textContent = s.error;
        errorDiv.style.display = 'block';
      } else {
        errorDiv.style.display = 'none';
      }
    } catch (e) {
      console.warn('Monitor status poll failed:', e.message);
    }
  }

  // Poll status every 1 second — pairs with the ML service's 150ms batch classifier
  // and backend's 1s drain so an attack surfaces in the UI within ~1.5s end-to-end.
  updateStatus();
  setInterval(updateStatus, 1000);
})();
