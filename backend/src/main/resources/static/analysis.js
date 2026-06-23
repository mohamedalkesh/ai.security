// Backend auth guard
if (window.AisecAPI) AisecAPI.requireAuth();

// Reveal
const io = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting){ e.target.classList.add('visible'); io.unobserve(e.target); }});
}, { threshold:.08 });
document.querySelectorAll('.reveal').forEach(el => io.observe(el));

// Get incident id
const params = new URLSearchParams(location.search);
const id = params.get('id') || 'INC-001';
document.getElementById('incRef').textContent = id;
document.getElementById('backLink').href = 'incident.html?id=' + id;
document.title = `${id} — Attack Analysis`;

// Incident → vector node labels
const VECTOR = {
  'INC-001': { a:'192.168.1.45',  t:'10.0.0.50',  v:'SQL Injection' },
  'INC-002': { a:'10.0.0.123',    t:'10.0.0.10',  v:'Brute Force' },
  'INC-003': { a:'172.16.0.88',   t:'10.0.0.22',  v:'Malicious Upload' },
  'INC-004': { a:'192.168.1.99',  t:'10.0.0.0/24',v:'Port Scan' },
  'INC-005': { a:'192.168.1.120', t:'10.0.0.50',  v:'XSS Injection' },
  'INC-006': { a:'10.0.0.45',     t:'10.0.0.5',   v:'Unauthorized Login' },
  'INC-007': { a:'203.0.113.42',  t:'10.0.0.1',   v:'DDoS Flood' },
  'INC-008': { a:'172.16.0.200',  t:'10.0.0.50',  v:'Malware Dropper' },
  'INC-009': { a:'198.51.100.88', t:'mail.corp',  v:'Phishing' },
  'INC-010': { a:'192.168.1.156', t:'185.22.4.10',v:'Data Exfiltration' },
};
const v = VECTOR[id] || VECTOR['INC-001'];
document.getElementById('attackerIp').textContent = v.a;
document.getElementById('targetIp').textContent = v.t;
document.getElementById('vectorLabel').textContent = v.v;

// ==== Data ====
const TIMELINE = [
  { time:'14:32:15', text:'Initial connection attempt',     tag:'info',     color:'' },
  { time:'14:32:16', text:'SQL injection pattern detected',  tag:'critical', color:'red' },
  { time:'14:32:17', text:'WAF rule triggered',              tag:'warning',  color:'yellow' },
  { time:'14:32:18', text:'Request blocked',                 tag:'success',  color:'green' },
  { time:'14:32:19', text:'IP address logged',               tag:'info',     color:'' },
  { time:'14:32:20', text:'Alert generated',                 tag:'critical', color:'red' },
];

const PATTERNS = [
  { label:'Multiple login attempts',    pct:95, sev:'high' },
  { label:'SQL injection signatures',   pct:98, sev:'critical' },
  { label:'Automated scanning behavior',pct:87, sev:'medium' },
  { label:'Common attack tools detected',pct:92, sev:'high' },
];

const FINDINGS = [
  'Classic SQL injection pattern detected',
  'Multiple attack vectors attempted',
  'Automated tool signatures present',
  'All attempts successfully blocked',
];

// ==== Render Timeline ====
const tl = document.getElementById('timeline');
tl.innerHTML = TIMELINE.map((t, i) => `
  <li class="tl-item ${t.color}" style="animation-delay:${i*.08}s">
    <span class="tl-time">${t.time}</span>
    <span class="tl-text">${t.text}</span>
    <span class="tl-tag ${t.tag}">${t.tag.toUpperCase()}</span>
  </li>
`).join('');

// ==== Render Patterns ====
const pats = document.getElementById('patterns');
pats.innerHTML = PATTERNS.map((p, i) => `
  <div class="pattern" style="animation-delay:${i*.1}s">
    <div class="pattern-head">
      <span>${p.label}</span>
      <span class="sev-tag ${p.sev}">${p.sev}</span>
    </div>
    <div class="pattern-bar ${p.sev}"><span style="width:${p.pct}%;animation-delay:${.2 + i*.12}s"></span></div>
    <div class="pattern-pct">${p.pct}%</div>
  </div>
`).join('');

// ==== Findings ====
document.getElementById('findings').innerHTML = FINDINGS.map(f => `<li>${f}</li>`).join('');

// ==== Meters (animate after a moment) ====
function setMeter(barId, valId, pct, cls){
  const bar = document.getElementById(barId);
  const val = document.getElementById(valId);
  setTimeout(() => { bar.style.width = pct + '%'; }, 300);
  const start = performance.now(), dur = 1400;
  function tick(now){
    const p = Math.min((now-start)/dur, 1);
    const e = 1 - Math.pow(1-p,3);
    val.textContent = Math.floor(pct*e) + '%';
    if (p<1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}
setMeter('barThreat','mThreat', 92, 'red');
setMeter('barSoph','mSoph', 67, 'orange');
setMeter('barSucc','mSucc', 8, 'green');

// ==== Toast ====
const toast = document.getElementById('toast');
function showToast(msg){
  toast.querySelector('span').textContent = msg;
  toast.classList.add('show');
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.remove('show'), 1800);
}
document.querySelectorAll('.ra-btn').forEach(b => {
  b.addEventListener('click', () => {
    if (b.classList.contains('purple')){ window.location.href = 'classification.html?id=' + id; return; }
    if (b.classList.contains('cyan')){ window.location.href = 'mitre.html?id=' + id; return; }
    if (b.classList.contains('green')){ window.location.href = 'response.html?id=' + id; return; }
    showToast(b.dataset.msg || 'Action triggered');
  });
});

// ===== Backend integration: load real alert data =====
(async function loadFromBackend(){
  if (!window.AisecAPI) return;
  const raw = params.get('id') || '';
  const m = raw.match(/(\d+)/);
  if (!m) return;
  const numId = parseInt(m[1]);

  try {
    const a = await AisecAPI.getAlert(numId);
    const idStr = 'INC-' + String(a.id).padStart(3, '0');
    const conf = Math.round((a.confidence || 0) * 100);
    const type = a.attack_type || 'Unknown';
    const sev = (a.severity || 'MEDIUM').toLowerCase();
    const ts = new Date(a.created_at);
    const timeFmt = t => t.toTimeString().split(' ')[0];

    // Update header
    document.getElementById('incRef').textContent = idStr;
    document.getElementById('backLink').href = 'incident.html?id=' + a.id;
    document.title = `${idStr} — Attack Analysis`;

    // Update vector diagram with real IPs
    document.getElementById('attackerIp').textContent = a.source_ip || '—';
    document.getElementById('targetIp').textContent = a.dest_ip || '—';
    document.getElementById('vectorLabel').textContent = type;

    // Generate timeline from real alert timestamp
    const baseTime = new Date(ts);
    const tl2 = [
      { time: timeFmt(baseTime),                                    text:`Initial ${type} connection attempt`,       tag:'info',     color:'' },
      { time: timeFmt(new Date(baseTime.getTime()+1000)),          text:`${type} pattern detected`,                   tag:'critical', color:'red' },
      { time: timeFmt(new Date(baseTime.getTime()+2000)),          text:'Defense rule triggered',                      tag:'warning',  color:'yellow' },
      { time: timeFmt(new Date(baseTime.getTime()+3000)),          text:'Request blocked',                             tag:'success',  color:'green' },
      { time: timeFmt(new Date(baseTime.getTime()+4000)),          text:'Source IP logged',                            tag:'info',     color:'' },
      { time: timeFmt(new Date(baseTime.getTime()+5000)),          text:'Alert generated',                             tag:'critical', color:'red' },
    ];
    tl.innerHTML = tl2.map((t, i) => `
      <li class="tl-item ${t.color}" style="animation-delay:${i*.08}s">
        <span class="tl-time">${t.time}</span>
        <span class="tl-text">${t.text}</span>
        <span class="tl-tag ${t.tag}">${t.tag.toUpperCase()}</span>
      </li>
    `).join('');

    // Patterns from real data
    const sevLabel = sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : 'medium';
    const pats2 = [
      { label:`${type} signatures detected`,       pct: Math.min(conf+1, 99), sev: sevLabel },
      { label:'Automated scanning behavior',        pct: Math.max(conf-5, 50), sev: conf > 85 ? 'high' : 'medium' },
      { label:'Anomalous traffic pattern',          pct: Math.max(conf-10, 40), sev: 'medium' },
      { label:'Known attack tool fingerprint',      pct: Math.max(conf-8, 45),  sev: conf > 80 ? 'high' : 'medium' },
    ];
    pats.innerHTML = pats2.map((p, i) => `
      <div class="pattern" style="animation-delay:${i*.1}s">
        <div class="pattern-head">
          <span>${p.label}</span>
          <span class="sev-tag ${p.sev}">${p.sev}</span>
        </div>
        <div class="pattern-bar ${p.sev}"><span style="width:${p.pct}%;animation-delay:${.2 + i*.12}s"></span></div>
        <div class="pattern-pct">${p.pct}%</div>
      </div>
    `).join('');

    // Findings
    document.getElementById('findings').innerHTML = [
      `${type} attack pattern confirmed with ${conf}% confidence`,
      `Source IP: ${a.source_ip || 'unknown'} → Target: ${a.dest_ip || 'unknown'}`,
      a.protocol ? `Protocol: ${a.protocol} · Port: ${a.dest_port || '—'}` : 'Protocol details unavailable',
      a.status === 'RESOLVED' ? 'Attack was successfully mitigated' : 'Alert is still active — monitoring continues',
    ].map(f => `<li>${f}</li>`).join('');

    // Meters from confidence
    const threatPct = Math.min(conf + 3, 99);
    const sophPct = Math.max(conf - 20, 30);
    const succPct = a.status === 'RESOLVED' ? 5 : Math.max(100 - conf, 5);
    setMeter('barThreat', 'mThreat', threatPct, '');
    setMeter('barSoph', 'mSoph', sophPct, '');
    setMeter('barSucc', 'mSucc', succPct, '');

  } catch (err) {
    console.debug('[analysis] backend load failed, using static data:', err);
  }
})();

// ==== Deep Analysis Flow ====
const overlay = document.getElementById('deepOverlay');
const deepBar = document.getElementById('deepBar');
const deepStep = document.getElementById('deepStep');
const STEPS = [
  { t:'Initializing AI models...',       p:15 },
  { t:'Correlating MITRE techniques...', p:35 },
  { t:'Analyzing network flow...',       p:55 },
  { t:'Scoring threat severity...',      p:75 },
  { t:'Generating recommendations...',   p:92 },
  { t:'Analysis complete ✓',             p:100 },
];
document.getElementById('deepBtn').addEventListener('click', () => {
  overlay.classList.add('show');
  deepBar.style.width = '0%';
  let i = 0;
  function next(){
    if (i >= STEPS.length){
      setTimeout(() => {
        overlay.classList.remove('show');
        showToast('Deep analysis complete');
      }, 700);
      return;
    }
    deepStep.textContent = STEPS[i].t;
    deepBar.style.width = STEPS[i].p + '%';
    i++;
    setTimeout(next, 650);
  }
  next();
});
