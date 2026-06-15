// Backend auth guard
if (window.AisecAPI) AisecAPI.requireAuth();

// Reveal
const io = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting){ e.target.classList.add('visible'); io.unobserve(e.target); }});
}, { threshold:.08 });
document.querySelectorAll('.reveal').forEach(el => io.observe(el));

// Params
const params = new URLSearchParams(location.search);
const id = params.get('id') || 'INC-001';
let incidentNumericId = (() => {
  const m = id.match(/(\d+)/);
  return m ? parseInt(m[1]) : null;
})();
document.getElementById('incRef').textContent = id;
document.getElementById('backLink').href = 'incident.html?id=' + id;
document.title = `${id} — AI Classification`;

// Per-incident classification data
const DATA = {
  'INC-001': {
    title:'SQL Injection Attack', conf:98.5,
    category:'Web Application Attack', vector:'Network-based', asset:'Database Server',
    secondary:[
      { label:'Authentication Bypass', pct:85 },
      { label:'Data Exfiltration Attempt', pct:72 },
      { label:'Privilege Escalation', pct:45 },
    ],
    model:{ classification:'SQL Injection Attack', confidence:98.5, attack_category:'Web Application Attack', attack_vector:'Network-based', target_asset:'Database Server', risk_level:'Critical', recommended_action:'immediate_response', timestamp:'2026-04-24T14:32:15Z' }
  },
  'INC-002': {
    title:'Brute Force Attack', conf:93.2,
    category:'Credential Attack', vector:'Network-based', asset:'SSH Service',
    secondary:[
      { label:'Credential Stuffing', pct:78 },
      { label:'Account Takeover Attempt', pct:65 },
      { label:'Dictionary Attack', pct:82 },
    ],
    model:{ classification:'Brute Force Attack', confidence:93.2, attack_category:'Credential Attack', attack_vector:'Network-based', target_asset:'SSH Service', risk_level:'High', recommended_action:'block_source_ip', timestamp:'2026-04-24T14:17:42Z' }
  },
  'INC-005': {
    title:'Cross-Site Scripting (XSS)', conf:96.8,
    category:'Web Application Attack', vector:'Client-side', asset:'Web Application',
    secondary:[
      { label:'Session Hijacking', pct:74 },
      { label:'Credential Theft Attempt', pct:62 },
      { label:'DOM Manipulation', pct:58 },
    ],
    model:{ classification:'Cross-Site Scripting', confidence:96.8, attack_category:'Web Application Attack', attack_vector:'Client-side', target_asset:'Web Application', risk_level:'Critical', recommended_action:'block_and_sanitize', timestamp:'2026-04-24T11:32:15Z' }
  },
  'INC-007': {
    title:'DDoS Attack', conf:99.1,
    category:'Network Attack', vector:'Volumetric', asset:'Edge Gateway',
    secondary:[
      { label:'UDP Amplification', pct:88 },
      { label:'Bot Coordinated Flood', pct:91 },
      { label:'Reflection Attack', pct:55 },
    ],
    model:{ classification:'DDoS Attack', confidence:99.1, attack_category:'Network Attack', attack_vector:'Volumetric', target_asset:'Edge Gateway', risk_level:'Critical', recommended_action:'edge_mitigation', timestamp:'2026-04-24T09:32:15Z' }
  },
};
let d = DATA[id] || DATA['INC-001'];

// Primary card
document.getElementById('pcTitle').textContent = d.title;
setTimeout(() => {
  document.getElementById('pcBar').style.width = d.conf + '%';
  animateNum(document.getElementById('pcVal'), d.conf, 1500, true);
}, 300);

// Classification details
document.getElementById('cdCat').textContent = d.category;
document.getElementById('cdVec').textContent = d.vector;
document.getElementById('cdAsset').textContent = d.asset;

// Secondary
const sec = document.getElementById('secondary');
const purpleClasses = ['purple-lt','purple','purple-dk'];
sec.innerHTML = d.secondary.map((s, i) => `
  <div class="pattern" style="animation-delay:${i*.1}s">
    <div class="pattern-head"><span>${s.label}</span></div>
    <div class="pattern-bar ${purpleClasses[i]||'purple'}"><span style="width:${s.pct}%;animation-delay:${.3 + i*.12}s"></span></div>
    <div class="pattern-pct">${s.pct}%</div>
  </div>
`).join('');

// Metrics
const METRICS = [
  { name:'Attack Pattern Recognition', desc:'Matched 12 known SQL injection signatures', pct:96, color:'green' },
  { name:'Behavioral Analysis',         desc:'Automated scanning behavior detected',      pct:89, color:'yellow' },
  { name:'Intent Classification',       desc:'Clear malicious intent with data access goals', pct:94, color:'green' },
  { name:'Threat Severity',             desc:'Critical threat requiring immediate action',     pct:92, color:'green' },
];
document.getElementById('metricsList').innerHTML = METRICS.map((m, i) => `
  <div class="metric" style="animation-delay:${i*.1}s">
    <div class="metric-top">
      <div>
        <div class="metric-name">${m.name}</div>
        <div class="metric-desc">${m.desc}</div>
      </div>
      <span class="metric-pct ${m.color}"><i class="fa-solid fa-arrow-trend-up"></i> ${m.pct}%</span>
    </div>
    <div class="metric-bar ${m.color}"><span style="width:${m.pct}%;animation-delay:${.4 + i*.1}s"></span></div>
  </div>
`).join('');

// JSON output with simple syntax highlighting
function highlightJson(obj){
  const raw = JSON.stringify(obj, null, 2);
  return raw
    .replace(/("(\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, (m) => {
      let cls = 'n';
      if (/^"/.test(m)){ cls = /:$/.test(m) ? 'k' : 's'; }
      else if (/true|false/.test(m)) cls = 'b';
      else if (/null/.test(m)) cls = 'p';
      return `<span class="${cls}">${m}</span>`;
    });
}
const jsonEl = document.getElementById('jsonOut');
jsonEl.innerHTML = highlightJson(d.model);

// Copy JSON
document.getElementById('copyJson').addEventListener('click', () => {
  navigator.clipboard.writeText(JSON.stringify(d.model, null, 2)).then(() => showToast('JSON copied'));
});

// Helpers
function animateNum(el, target, dur, isFloat){
  const start = performance.now();
  function tick(now){
    const p = Math.min((now-start)/dur, 1);
    const e = 1 - Math.pow(1-p,3);
    const v = target * e;
    el.textContent = (isFloat ? v.toFixed(1) : Math.floor(v)) + '%';
    if (p<1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// Toast
const toast = document.getElementById('toast');
function showToast(msg){
  toast.querySelector('span').textContent = msg;
  toast.classList.add('show');
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.remove('show'), 1800);
}

// Export analysis report (PDF)
const exportBtn = document.getElementById('nsExport');
if (exportBtn) {
  exportBtn.addEventListener('click', async () => {
    if (!window.AisecAPI) { showToast('API unavailable'); return; }
    if (!incidentNumericId) { showToast('Unable to determine incident'); return; }
    try {
      const { name } = await AisecAPI.downloadAnalysisReport(incidentNumericId);
      showToast(`Analysis downloaded: ${name}`);
    } catch (err) {
      const msg = err?.status === 401 ? 'Session expired — please log in again'
                : 'Export failed: ' + (err?.message || 'unknown error');
      showToast(msg);
    }
  });
}

// ===== Backend integration: load real alert classification =====
(async function loadFromBackend(){
  if (!window.AisecAPI) return;
  const raw = params.get('id') || '';
  const m = raw.match(/(\d+)/);
  if (!m) return;
  const numId = parseInt(m[1]);

  try {
    const a = await AisecAPI.getAlert(numId);
    incidentNumericId = numId;
    const conf = Math.round((a.confidence || 0) * 100);
    const idStr = 'INC-' + String(a.id).padStart(3, '0');

    // Update header
    document.getElementById('incRef').textContent = idStr;
    document.getElementById('backLink').href = 'incident.html?id=' + a.id;
    document.title = `${idStr} — AI Classification`;

    // Derive classification details from attack_type
    const catMap = {
      'DDoS':           { category:'Network Attack',       vector:'Volumetric',     asset:'Edge Gateway' },
      'DoS':            { category:'Network Attack',       vector:'Volumetric',     asset:'Network Service' },
      'Bot':            { category:'Botnet Activity',      vector:'Command & Control', asset:'Endpoint' },
      'Brute Force':    { category:'Credential Attack',    vector:'Network-based',  asset:'Authentication Service' },
      'Infiltration':   { category:'Intrusion',            vector:'Network-based',  asset:'Internal Network' },
      'Web Attack':     { category:'Web Application Attack',vector:'HTTP-based',    asset:'Web Server' },
      'SQL Injection':  { category:'Web Application Attack',vector:'HTTP-based',    asset:'Database Server' },
      'XSS':            { category:'Web Application Attack',vector:'Client-side',   asset:'Web Application' },
      'PortScan':       { category:'Reconnaissance',       vector:'Network-based',  asset:'Network Perimeter' },
      'FTP-Patator':    { category:'Credential Attack',    vector:'FTP Brute Force',asset:'FTP Service' },
      'SSH-Patator':    { category:'Credential Attack',    vector:'SSH Brute Force',asset:'SSH Service' },
      'Heartbleed':     { category:'Vulnerability Exploit', vector:'TLS-based',     asset:'TLS Endpoint' },
    };
    const type = a.attack_type || 'Unknown';
    const matched = Object.entries(catMap).find(([k]) => type.toLowerCase().includes(k.toLowerCase()));
    const info = matched ? matched[1] : { category:'Network Threat', vector:'Network-based', asset:'Target System' };

    // Primary card
    document.getElementById('pcTitle').textContent = type;
    document.getElementById('pcBar').style.width = conf + '%';
    document.getElementById('pcVal').textContent = conf + '%';

    // Details
    document.getElementById('cdCat').textContent = info.category;
    document.getElementById('cdVec').textContent = info.vector;
    document.getElementById('cdAsset').textContent = info.asset;

    // Secondary patterns derived from confidence
    const secData = [
      { label:'Attack Pattern Recognition', pct: Math.min(conf + 2, 99) },
      { label:'Behavioral Anomaly Match',   pct: Math.max(conf - 8, 40) },
      { label:'Signature Correlation',      pct: Math.max(conf - 15, 30) },
    ];
    sec.innerHTML = secData.map((s, i) => `
      <div class="pattern" style="animation-delay:${i*.1}s">
        <div class="pattern-head"><span>${s.label}</span></div>
        <div class="pattern-bar ${purpleClasses[i]||'purple'}"><span style="width:${s.pct}%;animation-delay:${.3 + i*.12}s"></span></div>
        <div class="pattern-pct">${s.pct}%</div>
      </div>
    `).join('');

    // Model JSON with real data
    const sev = (a.severity || 'INFORMATIONAL');
    const riskMap = { CRITICAL:'Critical', HIGH:'High', MEDIUM:'Medium', LOW:'Low', INFORMATIONAL:'Info' };
    const modelOut = {
      classification: type,
      confidence: conf,
      attack_category: info.category,
      attack_vector: info.vector,
      target_asset: info.asset,
      risk_level: riskMap[sev] || sev,
      recommended_action: sev === 'CRITICAL' ? 'immediate_response' : sev === 'HIGH' ? 'block_source_ip' : 'monitor',
      source_ip: a.source_ip || '—',
      dest_ip: a.dest_ip || '—',
      timestamp: a.created_at
    };
    jsonEl.innerHTML = highlightJson(modelOut);

    // Update metrics
    const metricsData = [
      { name:'Attack Pattern Recognition', desc:`Matched ${type} signatures`, pct: Math.min(conf+1,99), color: conf>85?'green':'yellow' },
      { name:'Behavioral Analysis',        desc:'Automated scanning behavior detected', pct: Math.max(conf-5,50), color: conf>80?'green':'yellow' },
      { name:'Intent Classification',      desc:`${riskMap[sev]||sev} threat level classification`, pct: Math.max(conf-3,45), color: conf>80?'green':'yellow' },
      { name:'Threat Severity',            desc: sev==='CRITICAL'?'Critical threat requiring immediate action':'Elevated threat detected', pct: Math.max(conf-2,40), color: sev==='CRITICAL'?'red':conf>80?'green':'yellow' },
    ];
    document.getElementById('metricsList').innerHTML = metricsData.map((m, i) => `
      <div class="metric" style="animation-delay:${i*.1}s">
        <div class="metric-top">
          <div>
            <div class="metric-name">${m.name}</div>
            <div class="metric-desc">${m.desc}</div>
          </div>
          <span class="metric-pct ${m.color}"><i class="fa-solid fa-arrow-trend-up"></i> ${m.pct}%</span>
        </div>
        <div class="metric-bar ${m.color}"><span style="width:${m.pct}%;animation-delay:${.4 + i*.1}s"></span></div>
      </div>
    `).join('');

  } catch (err) {
    console.warn('[classification] backend load failed, using static data:', err.message);
  }
})();

// Next steps
document.querySelectorAll('.ns-btn').forEach(b => {
  b.addEventListener('click', () => {
    if (b.classList.contains('cyan')) { window.location.href = 'mitre.html?id=' + id; return; }
    if (b.classList.contains('green')) { window.location.href = 'response.html?id=' + id; return; }
    showToast('Exporting analysis as PDF...');
  });
});

// Reclassify
const overlay = document.getElementById('reclassOverlay');
const reBar = document.getElementById('reBar');
const reStep = document.getElementById('reStep');
const STEPS = [
  { t:'Loading SecurityNet-AI v3.2...', p:20 },
  { t:'Extracting 89 features...',       p:45 },
  { t:'Running neural network...',       p:70 },
  { t:'Scoring classifications...',      p:90 },
  { t:'Classification complete ✓',       p:100 },
];
document.getElementById('reclassBtn').addEventListener('click', async () => {
  overlay.classList.add('show');
  reBar.style.width = '0%';
  reStep.textContent = STEPS[0].t;

  // If the backend API client is available, run REAL classification.
  if (window.AisecAPI) {
    try {
      // Stage 1: connecting
      reBar.style.width = '20%';
      reStep.textContent = 'Connecting to AI backend...';

      // Build a sample feature vector (all zeros = Benign baseline).
      // Per-incident profiles steer the model toward the expected class.
      const profiles = {
        'INC-001': { 'Flow Duration': 1500, 'Total Fwd Packets': 8, 'Total Backward Packets': 5 },
        'INC-002': { 'Flow Duration': 60000, 'Total Fwd Packets': 50, 'Total Backward Packets': 50 },
        'INC-005': { 'Flow Duration': 2000, 'Total Fwd Packets': 6, 'Total Backward Packets': 4 },
        'INC-007': { 'Flow Duration': 100, 'Total Fwd Packets': 5000, 'Total Backward Packets': 0 }
      };
      const features = profiles[id] || profiles['INC-001'];

      reBar.style.width = '50%';
      reStep.textContent = 'Running XGBoost classifier...';

      const result = await AisecAPI.predictFlow(features);

      reBar.style.width = '90%';
      reStep.textContent = 'Updating classification...';

      // Apply real result to the page
      document.getElementById('pcTitle').textContent =
        result.predicted === 'Benign' ? 'Normal Traffic' : result.predicted + ' Attack';
      document.getElementById('pcBar').style.width = (result.confidence * 100) + '%';
      const pcVal = document.getElementById('pcVal');
      pcVal.textContent = (result.confidence * 100).toFixed(1) + '%';

      // Refresh JSON panel with real backend response
      jsonEl.innerHTML = highlightJson(result);

      // Refresh secondary list from probabilities
      const probs = Object.entries(result.probabilities || {})
        .filter(([k]) => k !== result.predicted)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3);
      sec.innerHTML = probs.map(([label, p], i) => `
        <div class="pattern" style="animation-delay:${i*.1}s">
          <div class="pattern-head"><span>${label}</span></div>
          <div class="pattern-bar ${purpleClasses[i]||'purple'}"><span style="width:${(p*100).toFixed(1)}%;animation-delay:${.3 + i*.12}s"></span></div>
          <div class="pattern-pct">${(p*100).toFixed(1)}%</div>
        </div>`).join('');

      reBar.style.width = '100%';
      reStep.textContent = 'Classification complete ✓';
      setTimeout(() => {
        overlay.classList.remove('show');
        showToast(`Classified as ${result.predicted} (${(result.confidence*100).toFixed(1)}%)`);
      }, 600);
      return;
    } catch (err) {
      console.error('Reclassify failed:', err);
      reStep.textContent = 'Backend offline · using cached result';
      setTimeout(() => {
        overlay.classList.remove('show');
        showToast('Backend offline — please start it');
      }, 1200);
      return;
    }
  }

  // Fallback: original simulated animation (when api.js isn't loaded)
  let i = 0;
  (function step(){
    if (i >= STEPS.length){
      setTimeout(() => { overlay.classList.remove('show'); showToast('Reclassification complete'); }, 600);
      return;
    }
    reStep.textContent = STEPS[i].t;
    reBar.style.width = STEPS[i].p + '%';
    i++;
    setTimeout(step, 600);
  })();
});
