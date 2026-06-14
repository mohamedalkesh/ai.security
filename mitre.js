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
document.getElementById('incRef').textContent = id;
document.getElementById('backLink').href = 'incident.html?id=' + id;
document.title = `${id} — MITRE ATT&CK Mapping`;

// ===== Data =====
const CHAIN = [
  { name:'Initial Access',       ta:'TA0001', color:'red',    detected:true },
  { name:'Execution',             ta:'TA0002', color:'orange', detected:true },
  { name:'Persistence',           ta:'TA0003', color:'yellow', detected:false },
  { name:'Privilege Escalation',  ta:'TA0004', color:'green',  detected:true },
  { name:'Exfiltration',          ta:'TA0010', color:'blue',   detected:true },
];

const TACTICS = [
  {
    name:'Initial Access', ta:'TA0001', color:'red',
    techniques:[
      { id:'T1190', name:'Exploit Public-Facing Application', detected:true, conf:95,
        desc:'Adversaries exploit a weakness in an Internet-facing application to gain initial access to the network.' },
    ]
  },
  {
    name:'Execution', ta:'TA0002', color:'orange',
    techniques:[
      { id:'T1059', name:'Command and Scripting Interpreter', detected:true, conf:89,
        desc:'Adversaries abuse command and script interpreters to execute commands, scripts, or binaries.' },
      { id:'T1203', name:'Exploitation for Client Execution', detected:false, conf:0,
        desc:'Adversaries exploit software vulnerabilities in client applications to execute code.' },
    ]
  },
  {
    name:'Persistence', ta:'TA0003', color:'yellow',
    techniques:[
      { id:'T1505', name:'Server Software Component', detected:false, conf:0,
        desc:'Adversaries abuse legitimate extensible development features of servers to establish persistence.' },
    ]
  },
  {
    name:'Privilege Escalation', ta:'TA0004', color:'green',
    techniques:[
      { id:'T1068', name:'Exploitation for Privilege Escalation', detected:true, conf:67,
        desc:'Adversaries exploit vulnerabilities to gain higher-level permissions.' },
    ]
  },
  {
    name:'Exfiltration', ta:'TA0010', color:'blue',
    techniques:[
      { id:'T1041', name:'Exfiltration Over C2 Channel', detected:true, conf:75,
        desc:'Adversaries steal data by exfiltrating it over an existing command and control channel.' },
    ]
  },
];

const MITIGATIONS = [
  { id:'M1050', name:'Exploit Protection',        desc:'Deploy web application firewalls and input validation', status:'recommended', sev:'critical' },
  { id:'M1047', name:'Audit',                     desc:'Enable comprehensive logging and monitoring',            status:'implemented', sev:'high' },
  { id:'M1026', name:'Privileged Account Management', desc:'Implement least privilege access controls',         status:'recommended', sev:'high' },
  { id:'M1018', name:'User Account Management',   desc:'Regular review and update of user permissions',          status:'in-progress', sev:'medium' },
];

// ===== Render Chain =====
const chain = document.getElementById('chain');
let chainHtml = '';
CHAIN.forEach((c, i) => {
  chainHtml += `
    <div class="chain-step">
      <div class="chain-tile ${c.color}" data-ta="${c.ta}">
        ${c.detected ? '<span class="ch-dot"><i class="fa-solid fa-exclamation"></i></span>' : ''}
        ${c.name}
      </div>
      <div class="chain-id">${c.ta}</div>
    </div>
  `;
  if (i < CHAIN.length - 1){
    chainHtml += `<div class="chain-arrow"><i class="fa-solid fa-chevron-right"></i></div>`;
  }
});
chain.innerHTML = chainHtml;

// ===== Render Tactics =====
const tacticsWrap = document.getElementById('tacticsWrap');
tacticsWrap.innerHTML = TACTICS.map((t, ti) => `
  <section class="panel reveal tactic-block">
    <div class="tactic-title">
      <span class="tactic-dot ${t.color}"></span>
      <span>${t.name}</span>
      <span class="tactic-code">${t.ta}</span>
    </div>
    ${t.techniques.map((tk, i) => `
      <div class="tech-item ${tk.detected?'detected':''}" data-tid="${tk.id}" data-tname="${tk.name}" data-tdesc="${tk.desc}" data-tactic="${t.name}" data-conf="${tk.conf}" data-det="${tk.detected}" style="animation-delay:${i*.06}s">
        <span class="tech-id">${tk.id}</span>
        <span class="tech-name">${tk.name}</span>
        ${tk.detected ? '<span class="det-badge">Detected</span>' : ''}
        ${tk.detected ? `
          <div class="tech-conf">
            <div class="tech-bar"><span style="width:${tk.conf}%;animation-delay:${.3 + i*.1}s"></span></div>
            <span class="tech-pct">${tk.conf}%</span>
          </div>
        ` : ''}
      </div>
    `).join('')}
  </section>
`).join('');
// re-observe newly added .reveal blocks
document.querySelectorAll('.tactic-block.reveal').forEach(el => io.observe(el));

// ===== Mitigations =====
document.getElementById('mitigations').innerHTML = MITIGATIONS.map((m, i) => `
  <div class="mit-item ${m.sev}" style="animation-delay:${i*.08}s">
    <span class="mit-id">${m.id}</span>
    <div class="mit-body">
      <div class="mit-title-row">
        <span class="mit-name">${m.name}</span>
        <span class="status-tag ${m.status}">${m.status.replace('-',' ')}</span>
      </div>
      <div class="mit-desc">${m.desc}</div>
    </div>
    <span class="mit-sev ${m.sev}">${m.sev}</span>
  </div>
`).join('');

// ===== Detection Summary (animated) =====
setTimeout(() => {
  document.getElementById('barT').style.width = '80%';
  document.getElementById('barTk').style.width = '57%';
  document.getElementById('barC').style.width = '87%';
  animateText('dsT', '4/5', 1000);
  animateText('dsTk', '4/7', 1000);
  animateCount('dsC', 87, 1400, '%');
}, 300);

function animateCount(elId, target, dur, suffix=''){
  const el = document.getElementById(elId);
  const start = performance.now();
  (function tick(now){
    const p = Math.min((now-start)/dur, 1);
    const e = 1 - Math.pow(1-p,3);
    el.textContent = Math.floor(target*e) + suffix;
    if (p<1) requestAnimationFrame(tick);
  })(performance.now());
}
function animateText(elId, val, dur){
  setTimeout(() => document.getElementById(elId).textContent = val, dur*.7);
}

// ===== Technique Modal =====
const modal = document.getElementById('techModal');
const closeTech = document.getElementById('closeTech');
document.addEventListener('click', (e) => {
  const t = e.target.closest('.tech-item');
  if (t){
    document.getElementById('tId').textContent = t.dataset.tid;
    document.getElementById('tName').textContent = t.dataset.tname;
    document.getElementById('tDesc').textContent = t.dataset.tdesc;
    document.getElementById('tTactic').textContent = t.dataset.tactic;
    const det = t.dataset.det === 'true';
    document.getElementById('tDet').textContent = det ? 'Confirmed' : 'Not detected';
    const conf = document.getElementById('tConf');
    conf.textContent = det ? t.dataset.conf + '%' : 'N/A';
    conf.className = 'badge-sev ' + (det ? 'critical' : 'low');
    document.getElementById('tLink').href = `https://attack.mitre.org/techniques/${t.dataset.tid}/`;
    modal.classList.add('show');
  }
});
closeTech.addEventListener('click', () => modal.classList.remove('show'));
modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.remove('show'); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') modal.classList.remove('show'); });

// Toast
const toast = document.getElementById('toast');
function showToast(msg){
  toast.querySelector('span').textContent = msg;
  toast.classList.add('show');
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.remove('show'), 1800);
}
document.querySelectorAll('.ns-btn, .btn-action.export-mitre').forEach(b => {
  b.addEventListener('click', () => {
    const txt = b.textContent.trim();
    if (txt.includes('Generate Response Plan')){ window.location.href = 'response.html?id=' + id; return; }
    showToast(txt + ' triggered');
  });
});

// ===== Backend integration: map real alert to MITRE ATT&CK =====
(async function loadFromBackend(){
  if (!window.AisecAPI) return;
  const raw = params.get('id') || '';
  const m2 = raw.match(/(\d+)/);
  if (!m2) return;
  const numId = parseInt(m2[1]);

  try {
    const a = await AisecAPI.getAlert(numId);
    const idStr = 'INC-' + String(a.id).padStart(3, '0');
    const conf = Math.round((a.confidence || 0) * 100);
    const type = a.attack_type || 'Unknown';

    // Update header
    document.getElementById('incRef').textContent = idStr;
    document.getElementById('backLink').href = 'incident.html?id=' + a.id;
    document.title = `${idStr} — MITRE ATT&CK Mapping`;

    // ===== Attack-type to MITRE mapping =====
    const MITRE_MAP = {
      'DDoS':           { tech:'T1498', tactic:'Impact',              name:'Network Denial of Service' },
      'DoS':            { tech:'T1499', tactic:'Impact',              name:'Endpoint Denial of Service' },
      'Bot':            { tech:'T1583', tactic:'Resource Development', name:'Acquire Infrastructure' },
      'Brute Force':    { tech:'T1110', tactic:'Credential Access',   name:'Brute Force' },
      'Infiltration':   { tech:'T1071', tactic:'Command and Control', name:'Application Layer Protocol' },
      'Web Attack':     { tech:'T1190', tactic:'Initial Access',      name:'Exploit Public-Facing Application' },
      'SQL Injection':  { tech:'T1190', tactic:'Initial Access',      name:'Exploit Public-Facing Application' },
      'XSS':            { tech:'T1059', tactic:'Execution',           name:'Command and Scripting Interpreter' },
      'PortScan':       { tech:'T1046', tactic:'Discovery',           name:'Network Service Discovery' },
      'FTP-Patator':    { tech:'T1110', tactic:'Credential Access',   name:'Brute Force' },
      'SSH-Patator':    { tech:'T1110', tactic:'Credential Access',   name:'Brute Force' },
      'Heartbleed':     { tech:'T1190', tactic:'Initial Access',      name:'Exploit Public-Facing Application' },
    };

    // Use backend mitre fields first, fallback to mapping
    const mitreMatch = Object.entries(MITRE_MAP).find(([k]) => type.toLowerCase().includes(k.toLowerCase()));
    const mitreInfo = {
      tech:   a.mitre_technique || (mitreMatch ? mitreMatch[1].tech : 'T1190'),
      tactic: a.mitre_tactic    || (mitreMatch ? mitreMatch[1].tactic : 'Initial Access'),
      name:   mitreMatch ? mitreMatch[1].name : type,
    };

    // Build dynamic kill chain based on the detected tactic
    const TACTIC_ORDER = ['Initial Access','Execution','Persistence','Privilege Escalation','Defense Evasion','Credential Access','Discovery','Lateral Movement','Collection','Command and Control','Exfiltration','Impact'];
    const TA_MAP = {'Initial Access':'TA0001','Execution':'TA0002','Persistence':'TA0003','Privilege Escalation':'TA0004','Defense Evasion':'TA0005','Credential Access':'TA0006','Discovery':'TA0007','Lateral Movement':'TA0008','Collection':'TA0009','Command and Control':'TA0011','Exfiltration':'TA0010','Impact':'TA0040'};
    const COLORS = ['red','orange','yellow','green','blue','purple','red','orange','yellow','green','blue','purple'];

    // Select 5 chain steps centered around the detected tactic
    const tacIdx = TACTIC_ORDER.indexOf(mitreInfo.tactic);
    const startIdx = Math.max(0, Math.min(tacIdx - 2, TACTIC_ORDER.length - 5));
    const chainSlice = TACTIC_ORDER.slice(startIdx, startIdx + 5);
    const chainData = chainSlice.map((t, i) => ({
      name: t, ta: TA_MAP[t] || 'TA0001', color: COLORS[startIdx + i],
      detected: t === mitreInfo.tactic
    }));

    // Re-render chain
    let chainHtml2 = '';
    chainData.forEach((c, i) => {
      chainHtml2 += `
        <div class="chain-step">
          <div class="chain-tile ${c.color}" data-ta="${c.ta}">
            ${c.detected ? '<span class="ch-dot"><i class="fa-solid fa-exclamation"></i></span>' : ''}
            ${c.name}
          </div>
          <div class="chain-id">${c.ta}</div>
        </div>
      `;
      if (i < chainData.length - 1) chainHtml2 += '<div class="chain-arrow"><i class="fa-solid fa-chevron-right"></i></div>';
    });
    chain.innerHTML = chainHtml2;

    // Re-render tactics section with the detected technique
    const detectedTactic = {
      name: mitreInfo.tactic, ta: TA_MAP[mitreInfo.tactic] || 'TA0001',
      color: COLORS[TACTIC_ORDER.indexOf(mitreInfo.tactic)] || 'red',
      techniques: [
        { id: mitreInfo.tech, name: mitreInfo.name, detected: true, conf: conf,
          desc: `${type} detected from ${a.source_ip || 'unknown'} targeting ${a.dest_ip || 'unknown'}` }
      ]
    };
    tacticsWrap.innerHTML = `
      <section class="panel reveal tactic-block">
        <div class="tactic-title">
          <span class="tactic-dot ${detectedTactic.color}"></span>
          <span>${detectedTactic.name}</span>
          <span class="tactic-code">${detectedTactic.ta}</span>
        </div>
        ${detectedTactic.techniques.map((tk, i) => `
          <div class="tech-item detected" data-tid="${tk.id}" data-tname="${tk.name}" data-tdesc="${tk.desc}" data-tactic="${detectedTactic.name}" data-conf="${tk.conf}" data-det="true" style="animation-delay:${i*.06}s">
            <span class="tech-id">${tk.id}</span>
            <span class="tech-name">${tk.name}</span>
            <span class="det-badge">Detected</span>
            <div class="tech-conf">
              <div class="tech-bar"><span style="width:${tk.conf}%;animation-delay:.3s"></span></div>
              <span class="tech-pct">${tk.conf}%</span>
            </div>
          </div>
        `).join('')}
      </section>
    `;
    document.querySelectorAll('.tactic-block.reveal').forEach(el => io.observe(el));

    // Update detection summary
    document.getElementById('barT').style.width = '20%';
    document.getElementById('barTk').style.width = '100%';
    document.getElementById('barC').style.width = conf + '%';
    document.getElementById('dsT').textContent = '1/5';
    document.getElementById('dsTk').textContent = '1/1';
    document.getElementById('dsC').textContent = conf + '%';

    // Update mitigations with context
    const sev = (a.severity || 'MEDIUM').toLowerCase();
    const mits = [
      { id:'M1050', name:'Exploit Protection',           desc:`Deploy defenses against ${type}`,            status:'recommended', sev: sev === 'critical' ? 'critical' : 'high' },
      { id:'M1047', name:'Audit',                        desc:'Enable comprehensive logging and monitoring', status:'implemented', sev:'high' },
      { id:'M1030', name:'Network Segmentation',         desc:`Isolate ${a.dest_ip || 'target'} from external access`, status:'recommended', sev:'medium' },
      { id:'M1018', name:'User Account Management',      desc:'Review and restrict account permissions',      status:'in-progress', sev:'medium' },
    ];
    document.getElementById('mitigations').innerHTML = mits.map((m, i) => `
      <div class="mit-item ${m.sev}" style="animation-delay:${i*.08}s">
        <span class="mit-id">${m.id}</span>
        <div class="mit-body">
          <div class="mit-title-row">
            <span class="mit-name">${m.name}</span>
            <span class="status-tag ${m.status}">${m.status.replace('-',' ')}</span>
          </div>
          <div class="mit-desc">${m.desc}</div>
        </div>
        <span class="mit-sev ${m.sev}">${m.sev}</span>
      </div>
    `).join('');

  } catch (err) {
    console.warn('[mitre] backend load failed, using static data:', err.message);
  }
})();
