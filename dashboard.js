// ===== Animated counters =====
function animateNum(el, targetOverride){
  const target = targetOverride != null ? targetOverride : parseFloat(el.dataset.target);
  const isFloat = el.dataset.float === '1';
  const dur = 900;
  const start = performance.now();
  const from = parseFloat(el.textContent.replace(/[^0-9.]/g,'')) || 0;
  function tick(now){
    const p = Math.min((now - start) / dur, 1);
    const e = 1 - Math.pow(1 - p, 3);
    const v = from + (target - from) * e;
    el.textContent = isFloat ? v.toFixed(1) : Math.floor(v).toLocaleString();
    if (p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}
document.querySelectorAll('[data-target]').forEach(el => animateNum(el));

// ===== Reveal on scroll =====
const io = new IntersectionObserver((entries) => {
  entries.forEach(e => {
    if (e.isIntersecting){ e.target.classList.add('visible'); io.unobserve(e.target); }
  });
}, { threshold: .12 });
document.querySelectorAll('.reveal').forEach(el => io.observe(el));

// ===== DATA =====
// 24h timeline placeholders — populated from backend in the future
const HOURS = ['00:00','02:00','04:00','06:00','08:00','10:00','12:00','14:00','16:00','18:00','20:00','22:00'];
const attacksData = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const blockedData = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

// Detailed attack breakdown per hour (placeholders — populated by backend later)
const attackDetails = HOURS.map(() => ({ main:'No data', type:'low', src:'—', desc:'No incidents in this slot yet' }));

// ===== Custom tooltip handler =====
const tooltipEl = document.createElement('div');
tooltipEl.className = 'chart-tooltip';
document.querySelector('.chart-wrap').appendChild(tooltipEl);

function externalTooltip(context){
  const { chart, tooltip } = context;
  if (tooltip.opacity === 0){
    tooltipEl.classList.remove('show');
    return;
  }
  const idx = tooltip.dataPoints[0].dataIndex;
  const d = attackDetails[idx] || {};
  const a = attacksData[idx];
  const b = blockedData[idx];
  const missed = a - b;
  tooltipEl.innerHTML = `
    <div class="tt-time"><i class="fa-solid fa-clock"></i> ${HOURS[idx]}</div>
    <div class="tt-row">Attacks: <strong style="color:#ff6b6b">${a}</strong></div>
    <div class="tt-row">Blocked: <strong style="color:#51cf66">${b}</strong></div>
    <div class="tt-row">Breached: <strong style="color:${missed>0?'#ffa94d':'#51cf66'}">${missed}</strong></div>
    <div class="tt-attack">
      <span class="badge-sev ${d.type}">${(d.type||'').toUpperCase()}</span>
      <strong>${d.main}</strong>
    </div>
    <div class="tt-desc"><i class="fa-solid fa-location-crosshairs"></i> ${d.src}<br/>${d.desc}</div>
  `;
  // Position
  const rect = chart.canvas.getBoundingClientRect();
  const wrapRect = chart.canvas.parentElement.getBoundingClientRect();
  const x = tooltip.caretX;
  const y = tooltip.caretY;
  const tw = tooltipEl.offsetWidth;
  const th = tooltipEl.offsetHeight;
  let left = x + 14;
  if (left + tw > rect.width) left = x - tw - 14;
  let top = y - th/2;
  if (top < 0) top = 4;
  if (top + th > rect.height) top = rect.height - th - 4;
  tooltipEl.style.left = left + 'px';
  tooltipEl.style.top = top + 'px';
  tooltipEl.classList.add('show');
}

// ===== Threat Activity Chart =====
const ctx = document.getElementById('threatChart').getContext('2d');
const gradAtt = ctx.createLinearGradient(0,0,0,300);
gradAtt.addColorStop(0,'rgba(255,107,107,.35)');
gradAtt.addColorStop(1,'rgba(255,107,107,0)');
const gradBlk = ctx.createLinearGradient(0,0,0,300);
gradBlk.addColorStop(0,'rgba(34,184,207,.4)');
gradBlk.addColorStop(1,'rgba(34,184,207,0)');

const threatChart = new Chart(ctx, {
  type: 'line',
  data: {
    labels: HOURS,
    datasets: [
      {
        label:'Blocked', data: blockedData,
        borderColor:'#22b8cf', backgroundColor:gradBlk,
        fill:true, tension:.4, borderWidth:2.5,
        pointRadius:0, pointHoverRadius:7,
        pointHoverBackgroundColor:'#22b8cf',
        pointHoverBorderColor:'#fff', pointHoverBorderWidth:2,
      },
      {
        label:'Attacks', data: attacksData,
        borderColor:'#ff6b6b', backgroundColor:gradAtt,
        fill:true, tension:.4, borderWidth:2.5,
        pointRadius:0, pointHoverRadius:7,
        pointHoverBackgroundColor:'#ff6b6b',
        pointHoverBorderColor:'#fff', pointHoverBorderWidth:2,
      },
    ]
  },
  options: {
    responsive:true, maintainAspectRatio:false,
    interaction:{ mode:'index', intersect:false },
    plugins:{
      legend:{ display:false },
      tooltip:{ enabled:false, external: externalTooltip }
    },
    scales:{
      x:{
        grid:{ color:'rgba(255,255,255,.04)', drawBorder:false },
        ticks:{ color:'#8ea0b8', font:{ size:11 } }
      },
      y:{
        grid:{ color:'rgba(255,255,255,.05)', drawBorder:false },
        ticks:{ color:'#8ea0b8', font:{ size:11 }, stepSize:10 },
        beginAtZero:true
      }
    },
    animation:{ duration:1400, easing:'easeOutCubic' }
  },
  plugins:[{
    id:'verticalLine',
    afterDraw: (chart) => {
      const act = chart.tooltip?._active;
      if (act && act.length){
        const x = act[0].element.x;
        const top = chart.chartArea.top;
        const bot = chart.chartArea.bottom;
        const c = chart.ctx;
        c.save();
        c.beginPath();
        c.setLineDash([4,4]);
        c.moveTo(x, top); c.lineTo(x, bot);
        c.lineWidth = 1; c.strokeStyle = 'rgba(34,184,207,.5)';
        c.stroke(); c.restore();
      }
    }
  }]
});

// ===== Range tabs (demo) =====
document.querySelectorAll('#rangeTabs button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#rangeTabs button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    // Regenerate fake data
    const factor = btn.dataset.range === '7d' ? 3 : btn.dataset.range === '30d' ? 8 : 1;
    threatChart.data.datasets[0].data = blockedData.map(v => Math.round(v * factor * (0.8 + Math.random()*0.4)));
    threatChart.data.datasets[1].data = attacksData.map(v => Math.round(v * factor * (0.8 + Math.random()*0.4)));
    threatChart.update();
  });
});

// ===== Attack Types Donut =====
// Empty by default — backend `/api/alerts/breakdown` populates this.
const types = [
  { label:'No data', pct:100, color:'#334155' },
];
const typesCtx = document.getElementById('typesChart').getContext('2d');
new Chart(typesCtx, {
  type:'doughnut',
  data:{
    labels: types.map(t=>t.label),
    datasets:[{
      data: types.map(t=>t.pct),
      backgroundColor: types.map(t=>t.color),
      borderColor:'#16243d', borderWidth:3,
      hoverOffset:10, hoverBorderColor:'#22b8cf',
    }]
  },
  options:{
    responsive:true, maintainAspectRatio:false,
    cutout:'70%',
    plugins:{
      legend:{ display:false },
      tooltip:{
        backgroundColor:'#0f1d35', borderColor:'rgba(34,184,207,.4)', borderWidth:1,
        padding:12, titleColor:'#22b8cf', bodyColor:'#e6edf7',
        callbacks:{ label:(c)=> ` ${c.parsed}% of attacks` }
      }
    },
    animation:{ animateRotate:true, animateScale:true, duration:1400 }
  }
});

// Type legend
const legend = document.getElementById('typeLegend');
legend.innerHTML = types.map(t => `
  <li>
    <span class="swatch" style="background:${t.color}"></span>
    <span>${t.label}</span>
    <span class="pct">${t.pct}%</span>
  </li>
`).join('');

// ===== Helpers =====
function timeAgoShort(iso, arabic = false){
  if (!iso) return '';
  const d = (Date.now() - new Date(iso).getTime()) / 1000;
  if (!arabic) {
    if (d < 60)    return Math.floor(d) + 's ago';
    if (d < 3600)  return Math.floor(d/60) + 'm ago';
    if (d < 86400) return Math.floor(d/3600) + 'h ago';
    return Math.floor(d/86400) + 'd ago';
  }
  if (d < 60)    return `منذ ${Math.floor(d)} ثانية`;
  if (d < 3600)  return `منذ ${Math.floor(d/60)} دقيقة`;
  if (d < 86400) return `منذ ${Math.floor(d/3600)} ساعة`;
  return `منذ ${Math.floor(d/86400)} يوم`;
}

// ===== Notifications panel =====
const notifBtn   = document.getElementById('notifBtn');
const notifPanel = document.getElementById('notifPanel');
const notifDot   = document.getElementById('notifDot');
const notifList  = document.getElementById('notifList');
let   notifOpen  = false;
let   notifData  = [];

notifBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  notifOpen = !notifOpen;
  notifPanel.classList.toggle('show', notifOpen);
  if (notifOpen) renderNotifPanel();
});
document.addEventListener('click', (e) => {
  if (notifOpen && !document.getElementById('notifWrap').contains(e.target)){
    notifOpen = false;
    notifPanel.classList.remove('show');
  }
});
document.getElementById('notifMarkAll').addEventListener('click', () => {
  notifDot.style.display = 'none';
  notifList.querySelectorAll('.notif-item.unread').forEach(li => li.classList.remove('unread'));
});

function renderNotifPanel(){
  if (!notifData.length){
    notifList.innerHTML = '<li class="notif-empty">لا توجد إشعارات جديدة</li>';
    return;
  }
  notifList.innerHTML = notifData.map((a, i) => {
    const sevClass = (a.severity || 'low').toLowerCase();
    return `<li class="notif-item unread" onclick="location.href='incident.html?id=${a.id}'">
      <span class="notif-ico ${sevClass}"><i class="fa-solid fa-triangle-exclamation"></i></span>
      <div class="notif-body">
        <div class="notif-title">${a.attack_type || 'هجوم غير معروف'} <span class="badge-sev ${sevClass}" style="font-size:9px;padding:1px 5px">${a.severity||''}</span></div>
        <div class="notif-sub">المصدر: ${a.source_ip || '—'} · ${timeAgoShort(a.created_at, true)}</div>
      </div>
    </li>`;
  }).join('');
}

async function loadNotifications(){
  if (!window.AisecAPI) return;
  try {
    const page = await AisecAPI.listAlerts({ size: 8, status: 'NEW' });
    notifData = page.content || [];
    if (notifData.length > 0){
      notifDot.style.display = '';
      notifBtn.setAttribute('title', `${notifData.length} تنبيه جديد`);
    } else {
      notifDot.style.display = 'none';
    }
    if (notifOpen) renderNotifPanel();
  } catch {}
}

// ===== Backend connection =====
(function wireBackend(){
  if (!window.AisecAPI) return;
  if (!AisecAPI.requireAuth()) return;

  // Fill user chip from session
  const sess = AisecAPI.getSession();
  if (sess) {
    const name = sess.fullName || sess.username || 'User';
    const role = sess.role || 'Viewer';
    const initials = name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0,2);
    document.getElementById('userAvatar').textContent = initials;
    document.getElementById('userName').textContent   = name;
    document.getElementById('userRole').textContent   = role.charAt(0) + role.slice(1).toLowerCase();
  }

  // ---- Status pill (inject into header once) ----
  const header = document.querySelector('.dash-top') || document.querySelector('header');
  if (header && !document.getElementById('beStatus')) {
    const pill = document.createElement('div');
    pill.id = 'beStatus';
    pill.style.cssText = 'display:inline-flex;align-items:center;gap:8px;padding:5px 12px;border-radius:999px;background:rgba(255,255,255,.06);font-size:12px;font-weight:600;color:#cbd5e1;margin-left:auto;flex-shrink:0';
    pill.innerHTML = `<span id="beDot" style="width:8px;height:8px;border-radius:50%;background:#facc15;box-shadow:0 0 8px #facc15;flex-shrink:0"></span><span id="beTxt">Backend: connecting…</span>`;
    header.querySelector('.top-actions')?.before(pill) || header.appendChild(pill);
  }

  function setStatus(ok, text){
    const dot = document.getElementById('beDot');
    const txt = document.getElementById('beTxt');
    if (dot){ dot.style.background = ok ? '#22c55e' : '#ef4444'; dot.style.boxShadow = `0 0 8px ${ok?'#22c55e':'#ef4444'}`; }
    if (txt) txt.textContent = text;
  }
  async function checkHealth(){
    try {
      const h = await AisecAPI.health();
      const mlOk = h && h.ml && h.ml.status === 'ok';
      setStatus(mlOk, mlOk ? 'Backend + AI: ONLINE' : 'Backend ONLINE · AI offline');
    } catch { setStatus(false, 'Backend: OFFLINE'); }
  }
  checkHealth();
  setInterval(checkHealth, 15000);

  // ---- KPI Cards ----
  async function loadKpis(){
    try {
      const stats = await AisecAPI.alertStats();
      // Active Alerts card
      const activeEl = document.querySelector('.stat-card:nth-child(1) .stat-val');
      if (activeEl) animateNum(activeEl, stats.active ?? 0);

      // Threats Blocked card
      const blockedEl = document.querySelector('.stat-card:nth-child(2) .stat-val');
      if (blockedEl) animateNum(blockedEl, stats.resolved ?? 0);

      // System Health — 100% minus recent threat pressure; stays high if no recent alerts
      const total = stats.total || 0;
      const l24raw = stats.last24h || 0;
      const crit = stats.critical || 0;
      const healthPct = l24raw === 0 && crit === 0
        ? 99.9
        : parseFloat(Math.max(50, 100 - l24raw * 2 - crit * 5).toFixed(1));
      const healthSpan = document.querySelector('.stat-card:nth-child(3) [data-float="1"]');
      if (healthSpan) animateNum(healthSpan, healthPct);
      const healthBar = document.querySelector('.stat-card:nth-child(3) .progress-bar span');
      if (healthBar) healthBar.style.width = healthPct + '%';

      // Avg Response Time — derive from last24h density (cosmetic)
      const respTime = l24raw > 0 ? parseFloat((0.3 + l24raw * 0.05).toFixed(1)) : 0.3;
      const respSpan = document.querySelector('.stat-card:nth-child(4) [data-float="1"]');
      if (respSpan) animateNum(respSpan, respTime);

      // Trend badges
      const cards = document.querySelectorAll('.stat-card');
      if (cards[0]) { const t = cards[0].querySelector('.trend'); if (t) t.textContent = `+${l24raw} today`; }
      if (cards[1]) { const t = cards[1].querySelector('.trend'); if (t) t.textContent = `${stats.resolved ?? 0} resolved`; }

      // Donut center
      const dNum = document.getElementById('totalThreats');
      if (dNum) dNum.textContent = (total).toLocaleString();

      const vol = document.getElementById('live24h');
      if (vol) animateNum(vol, stats.last24h ?? 0);
      const trends = document.getElementById('liveTrends');
      if (trends) trends.textContent = stats.last24h
        ? `آخر 24 ساعة: ${stats.last24h} تنبيه جديد.`
        : 'لا توجد تنبيهات جديدة خلال آخر 24 ساعة.';
      const critBox = document.getElementById('liveCrit');
      if (critBox) critBox.textContent = `حرج: ${stats.critical ?? 0} · عالي: ${stats.high ?? 0}`;
    } catch (err) { console.warn('[KPIs]', err.message); }
  }

  // ---- Donut Chart (attack types) ----
  async function loadBreakdown(){
    try {
      const breakdown = await AisecAPI.alertBreakdown(); // [{type:"DDoS",count:5},...]
      const palette = ['#ff6b6b','#ffa94d','#ffd43b','#51cf66','#22b8cf','#9775fa','#fa7268'];
      const arr = Array.isArray(breakdown) ? breakdown : [];
      const total = arr.reduce((s, r) => s + (Number(r.count) || 0), 0);
      const sorted = [...arr].sort((a,b) => b.count - a.count);
      const dist = sorted.length
        ? sorted.map((r, i) => ({ label: r.type || 'Unknown', pct: total ? Math.round(r.count/total*100) : 0, color: palette[i%palette.length] }))
        : [{ label:'No data', pct:100, color:'#334155' }];

      const chart = Chart.getChart('typesChart');
      if (chart){
        chart.data.labels = dist.map(d=>d.label);
        chart.data.datasets[0].data = dist.map(d=>d.pct);
        chart.data.datasets[0].backgroundColor = dist.map(d=>d.color);
        chart.update('active');
      }
      const legend = document.getElementById('typeLegend');
      if (legend) legend.innerHTML = dist.map(d =>
        `<li><span class="swatch" style="background:${d.color}"></span><span>${d.label}</span><span class="pct">${d.pct}%</span></li>`
      ).join('');

      const top = dist[0];
      const typeEl = document.getElementById('liveType');
      const shareEl = document.getElementById('liveTypeShare');
      const trendEl = document.getElementById('liveTypeTrend');
      if (top && typeEl && shareEl && trendEl) {
        typeEl.textContent = top.label;
        shareEl.textContent = `يمثل ${top.pct}% من إجمالي الهجمات.`;
        trendEl.textContent = top.pct > 40 ? 'نوصي بزيادة المراقبة لهذا النوع.' : 'الحجم تحت السيطرة حاليًا.';
      } else if (typeEl && shareEl && trendEl) {
        typeEl.textContent = '—';
        shareEl.textContent = 'لا تتوفر بيانات توزيع بعد.';
        trendEl.textContent = 'Stay vigilant.';
      }
    } catch (err) { console.warn('[Breakdown]', err.message); }
  }

  // ---- Trend Chart (hourly from last 24h alerts) ----
  async function loadTrendChart(){
    try {
      const page = await AisecAPI.listAlerts({ size: 500 });
      const alerts = page.content || [];
      const now = Date.now();
      const hourBuckets = Array.from({length:12}, (_, i) => ({
        label: String(new Date(now - (11-i)*2*3600*1000).getHours()).padStart(2,'0') + ':00',
        attacks: 0, blocked: 0
      }));
      alerts.forEach(a => {
        const age = (now - new Date(a.created_at).getTime()) / 3600000; // hours ago
        if (age > 24) return;
        const bucket = 11 - Math.min(11, Math.floor(age / 2));
        hourBuckets[bucket].attacks++;
        if ((a.status||'').toUpperCase() === 'RESOLVED') hourBuckets[bucket].blocked++;
      });
      const chart = Chart.getChart('threatChart');
      if (chart){
        chart.data.labels = hourBuckets.map(b => b.label);
        chart.data.datasets[0].data = hourBuckets.map(b => b.blocked);  // Blocked
        chart.data.datasets[1].data = hourBuckets.map(b => b.attacks);  // Attacks
        chart.update('active');
      }
      // Sync global arrays for tooltip
      hourBuckets.forEach((b,i) => { attacksData[i] = b.attacks; blockedData[i] = b.blocked; HOURS[i] = b.label; });
    } catch (err) { console.warn('[TrendChart]', err.message); }
  }

  // ---- Recent Alerts panel ----
  async function loadRecent(){
    const box = document.getElementById('recentAlerts');
    if (!box) return;
    try {
      const page = await AisecAPI.listAlerts({ size: 5 });
      const list = page.content || [];
      if (!list.length){ box.innerHTML = '<div class="muted sm" style="padding:24px;text-align:center">No recent alerts</div>'; return; }
      box.innerHTML = list.map(a => `
        <div class="alert-item" onclick="location.href='incident.html?id=${a.id}'" style="cursor:pointer">
          <div class="a-id">INC-${String(a.id).padStart(3,'0')}</div>
          <div class="a-body">
            <div class="a-top"><span class="badge-sev ${(a.severity||'').toLowerCase()}">${a.severity||'—'}</span><span class="a-time muted sm">${timeAgoShort(a.created_at)}</span></div>
            <div class="a-title">${a.attack_type||'Unknown'}</div>
            <div class="a-src muted sm">Source: ${a.source_ip||'—'}</div>
          </div>
        </div>`).join('');

      const latest = list[0];
      const attackEl = document.getElementById('liveAttack');
      const metaEl = document.getElementById('liveAttackMeta');
      const footerEl = document.getElementById('liveAttackFooter');
      if (latest && attackEl && metaEl && footerEl) {
        attackEl.textContent = latest.attack_type || 'هجوم غير معروف';
        metaEl.textContent = `آخر تحديث منذ ${timeAgoShort(latest.created_at)} · شدة ${latest.severity || '—'}`;
        footerEl.textContent = `المصدر: ${latest.source_ip || '—'} · الهدف: ${latest.dest_ip || '—'}`;
      }
    } catch { box.innerHTML = '<div class="muted sm" style="padding:24px;text-align:center">Failed to load alerts</div>'; }
  }

  // ---- Activity Log ----
  const actLog = [];
  function addLog(icon, color, text){
    actLog.unshift({ icon, color, text, time: new Date() });
    if (actLog.length > 20) actLog.pop();
    const el = document.getElementById('activityLog');
    if (!el) return;
    el.innerHTML = actLog.map(e => `
      <li class="log-item">
        <span class="log-ico" style="color:${e.color}"><i class="fa-solid ${e.icon}"></i></span>
        <span class="log-txt">${e.text}</span>
        <span class="log-time muted sm">${timeAgoShort(e.time.toISOString())}</span>
      </li>`).join('');
  }

  // ---- Initial load ----
  async function initialLoad(){
    await Promise.allSettled([loadKpis(), loadBreakdown(), loadTrendChart(), loadRecent(), loadNotifications()]);
    addLog('fa-circle-check','#22c55e','تم تحديث لوحة التحكم من الخادم');
    AisecAPI.modelInfo()
      .then(i => addLog('fa-brain','#22b8cf',`نموذج الذكاء الاصطناعي: ${i.model_type||'XGBoost'} · ${i.n_features} ميزة`))
      .catch(() => {});
  }
  initialLoad();

  // ---- Auto-refresh every 30s ----
  setInterval(() => {
    loadKpis();
    loadBreakdown();
    loadTrendChart();
    loadRecent();
    loadNotifications();
  }, 30000);

  // ---- WebSocket live updates ----
  let wsRetry = 0;
  function connectWS(){
    const ws = AisecAPI.connectAlertsWS({
      onOpen: () => { wsRetry = 0; addLog('fa-plug','#22b8cf','تم الاتصال بالتحديث اللحظي — البث المباشر نشط'); },
      onMessage: (msg) => {
        if (!msg) return;
        if (msg.type === 'alert'){
          addLog('fa-bell','#ff6b6b', `تنبيه جديد: ${msg.attackType||msg.attack_type||'غير معروف'} (${msg.severity||''})`);
          loadKpis(); loadRecent(); loadBreakdown(); loadNotifications();
        } else if (msg.type === 'scan_complete'){
          addLog('fa-magnifying-glass','#ffa94d','اكتمل فحص الشبكة — يتم تحديث البيانات');
          loadKpis(); loadRecent(); loadBreakdown(); loadTrendChart(); loadNotifications();
        }
      },
      onClose: () => {
        wsRetry++;
        const delay = Math.min(wsRetry * 5000, 30000);
        setTimeout(connectWS, delay);
      },
      onError: () => {}
    });
    return ws;
  }
  connectWS();
})();
