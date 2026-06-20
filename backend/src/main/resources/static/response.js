if (window.AisecAPI) AisecAPI.requireAuth();

// Reveal animations
const io = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting){ e.target.classList.add('visible'); io.unobserve(e.target); }});
}, { threshold:.08 });
document.querySelectorAll('.reveal').forEach(el => io.observe(el));

// URL params
const params = new URLSearchParams(location.search);
const rawId = params.get('id') || 'INC-001';
document.getElementById('incRef').textContent = rawId;
document.getElementById('backLink').href = 'incident.html?id=' + rawId;
document.getElementById('backBtn2').addEventListener('click', () => window.location.href = 'incident.html?id=' + rawId);
document.title = `${rawId} — Response Plan`;

// ===== PLAYBOOKS — one per AI-model attack class =====
function buildPlaybook(type, srcIp, dstIp) {
  const src = srcIp || '—';
  const dst = dstIp || '—';

  const books = {
    'DDoS': [
      { title:'Enable Rate Limiting',        desc:`Throttle traffic from ${src} — limit to 100 req/s`,            dur:'< 1 min', sev:'critical', type:'auto',   action:'blockIp',  detail:'Rate limiting prevents bandwidth exhaustion at the edge, before traffic reaches backend servers.',             why:'DDoS floods bandwidth — throttling at the source preserves service availability for legitimate users.' },
      { title:'Blackhole Source Subnet',     desc:`Add ${src}/24 to BGP null-route`,                              dur:'1 min',   sev:'critical', type:'auto',   action:'blockIp',  detail:'BGP blackholing drops all traffic from the attacker subnet before it enters your network.',                   why:'Entire /24 subnets are often coordinated in volumetric DDoS; blocking the range stops the campaign.' },
      { title:'Enable Traffic Scrubbing',    desc:'Route inbound traffic through scrubbing center',               dur:'5 min',   sev:'high',     type:'manual', action:null,       detail:'Scrubbing centers use deep-packet inspection to separate attack traffic from legitimate users.',              why:'Protects servers while keeping the service online for real traffic.' },
      { title:'Scale Edge Capacity',         desc:'Auto-scale edge nodes and CDN to absorb flood volume',         dur:'2 min',   sev:'high',     type:'auto',   action:null,       detail:'Horizontal scaling temporarily adds capacity to match attack volume while mitigations take effect.',          why:'Buys time for upstream ISP null-routing coordination if the attack persists.' },
      { title:'Notify NOC Team',             desc:'Alert Network Operations Center of ongoing DDoS event',        dur:'< 1 min', sev:'medium',   type:'auto',   action:'notify',   detail:'Human oversight is critical during large-scale attacks that may evolve or shift vectors in real time.',      why:'NOC can coordinate with upstream ISP for null-routing if scrubbing alone is insufficient.' },
      { title:'Generate Incident Report',    desc:'Document attack timeline, vectors, and countermeasures',       dur:'5 min',   sev:'low',      type:'auto',   action:'report',   detail:'Reports capture attack magnitude, duration, affected services, and resolution for compliance evidence.',     why:'Required for SLA breach documentation and potential law enforcement or upstream provider coordination.' },
    ],
    'DoS': [
      { title:'Block Source IP',             desc:`Add ${src} to firewall blocklist immediately`,                 dur:'< 1 min', sev:'critical', type:'auto',   action:'blockIp',  detail:'Single-source DoS is straightforward to block — one IP drop rule stops the attack at the firewall level.', why:'DoS originates from a single host; unlike DDoS, a single IP block is sufficient to stop it.' },
      { title:'Enable Connection Limiting',  desc:`Restrict concurrent connections from ${src} to 10`,           dur:'1 min',   sev:'critical', type:'auto',   action:null,       detail:'TCP connection limits prevent resource exhaustion (SYN flood, slowloris) even if the IP block is bypassed.', why:'Defense in depth: connection limits protect the server stack independently of firewall rules.' },
      { title:'Analyze Attack Pattern',      desc:'Identify protocol, port, and payload signature of the DoS',   dur:'5 min',   sev:'high',     type:'manual', action:null,       detail:'Protocol and payload analysis (UDP flood vs SYN vs HTTP flood) guides targeted firewall rule creation.',   why:'Pattern analysis enables signature-based rules that block similar attacks from any source.' },
      { title:'Update Firewall Rules',       desc:'Add protocol-specific drop rules for this attack signature',   dur:'3 min',   sev:'high',     type:'auto',   action:null,       detail:'Firewall rules targeting the specific protocol/port abused are more precise than generic IP blocks.',        why:'Protocol-layer rules (e.g., UDP flood on port 53) block the attack even if the source IP rotates.' },
      { title:'Notify Security Team',        desc:'Alert on-call analysts of DoS event and resolution status',   dur:'< 1 min', sev:'medium',   type:'auto',   action:'notify',   detail:'Human review confirms no concurrent attack or lateral movement is occurring under the DoS cover.',           why:'DoS is frequently used as a distraction for a simultaneous breach attempt.' },
      { title:'Generate Incident Report',    desc:'Document attack vector, duration, and resolution timeline',   dur:'3 min',   sev:'low',      type:'auto',   action:'report',   detail:'Post-incident reports capture the full timeline and inform firewall hardening recommendations.',             why:'Review of DoS events improves detection sensitivity and reduces future response time.' },
    ],
    'Brute Force': [
      { title:'Block Source IP',             desc:`Add ${src} to firewall blocklist`,                            dur:'< 1 min', sev:'critical', type:'auto',   action:'blockIp',  detail:'Immediately terminates the brute force session from this source at the network level.',                      why:'Speed is critical — every second of active brute force increases the probability of credential breach.' },
      { title:'Lock Targeted Accounts',      desc:`Temporarily lock accounts on ${dst} with failed attempts`,   dur:'1 min',   sev:'critical', type:'auto',   action:null,       detail:'Account lockout after N failed attempts prevents credential guessing regardless of IP rotation.',            why:'Defense in depth: block at IP level AND at account level to handle distributed brute force.' },
      { title:'Enforce MFA on Target',       desc:`Enable multi-factor authentication on service at ${dst}`,    dur:'5 min',   sev:'high',     type:'manual', action:null,       detail:'MFA renders brute-forced passwords useless without a physical second factor.',                               why:'Permanent protection even when the attacker changes source IPs or uses credential stuffing.' },
      { title:'Audit for Successful Logins', desc:'Check if any credentials from this attack wave succeeded',   dur:'10 min',  sev:'high',     type:'manual', action:null,       detail:'Cross-reference authentication logs against the attack window to detect any successful logins.',             why:'Some credentials may have succeeded before the system detected the attack pattern.' },
      { title:'Reset Compromised Accounts',  desc:'Force password reset for any accounts showing success flag', dur:'3 min',   sev:'medium',   type:'auto',   action:null,       detail:'Invalidate all active sessions and force credential rotation for any potentially compromised accounts.',     why:'Ensures the attacker loses access even if a password was successfully guessed during the attack.' },
      { title:'Generate Compliance Report',  desc:'Document credential attack for regulatory compliance',        dur:'5 min',   sev:'low',      type:'auto',   action:'report',   detail:'Brute force attacks on user credentials may require notification under GDPR, HIPAA, or PCI DSS.',          why:'Regulatory frameworks mandate timely reporting of credential-related security incidents.' },
    ],
    'Port Scan': [
      { title:'Block Source IP',             desc:`Add ${src} to firewall blocklist — active reconnaissance`,   dur:'< 1 min', sev:'critical', type:'auto',   action:'blockIp',  detail:'Port scans are the reconnaissance phase of targeted attacks. Blocking the scanner prevents intelligence gathering.', why:'Reconnaissance is phase 1 of the cyber kill chain — interrupting it prevents subsequent attack phases.' },
      { title:'Enable Scan Detection Rules', desc:'Add rate-based port-scan detection to firewall policy',      dur:'2 min',   sev:'high',     type:'auto',   action:null,       detail:'Detection rules trigger on rapid multi-port connection attempts, blocking new scanners automatically.',        why:'Proactive rules catch future scanners before they complete reconnaissance.' },
      { title:'Audit Exposed Services',      desc:`Review services visible to ${src} on ${dst}`,               dur:'10 min',  sev:'high',     type:'manual', action:null,       detail:'Identify which ports and services the scanner discovered — unnecessary exposure should be eliminated.',        why:'Attack surface reduction: every open port is a potential entry point for the attacker.' },
      { title:'Review Firewall Rules',       desc:'Verify only necessary ports are reachable from external networks', dur:'8 min', sev:'medium',type:'manual', action:null,       detail:'Firewall audit enforces the principle of least privilege — only business-required ports should be reachable.', why:'Discovered open ports become targets in the next attack phase (exploitation).' },
      { title:'Notify Security Team',        desc:'Alert team of active reconnaissance — possible targeted attack', dur:'< 1 min', sev:'medium',type:'auto',  action:'notify',   detail:'Port scans often precede targeted exploitation — security team should prepare for follow-up activity.',       why:'Early warning enables proactive hardening before the attacker moves to exploitation.' },
      { title:'Log Scan for Threat Intel',   desc:'Record scan pattern and source IP in threat intelligence DB', dur:'3 min',   sev:'low',     type:'auto',   action:'report',   detail:'Threat intel logging identifies repeat scanners and correlates activity across multiple targets.',             why:'Coordinated scan campaigns often precede large-scale attacks — pattern correlation is critical.' },
    ],
    'Bot': [
      { title:'Block Source IP',             desc:`Add ${src} to firewall blocklist — bot traffic detected`,    dur:'< 1 min', sev:'critical', type:'auto',   action:'blockIp',  detail:'Immediate IP block stops bot traffic while deeper fingerprinting analysis runs in parallel.',                why:'Bots perform credential stuffing, content scraping, or C2 communication — all damaging at scale.' },
      { title:'Deploy Bot Challenge',        desc:'Enable CAPTCHA / JS challenge for suspicious traffic pattern', dur:'2 min',  sev:'critical', type:'auto',   action:null,       detail:'Browser fingerprint challenges distinguish human users from automated bots without disrupting legitimate traffic.', why:'Bots cannot solve JavaScript execution challenges, filtering them without blocking real users.' },
      { title:'Fingerprint Bot Campaign',    desc:`Analyze request patterns from ${src} for campaign signature`,  dur:'8 min',  sev:'high',    type:'manual', action:null,       detail:'Bot fingerprinting (user agent, request cadence, header anomalies) creates signatures that work across IP rotations.', why:'Sophisticated bots rotate source IPs — fingerprint-based blocking catches them regardless of source.' },
      { title:'Block Bot User Agents',       desc:'Add identified bot UA strings to WAF deny rules',            dur:'3 min',   sev:'high',     type:'auto',   action:null,       detail:'Known bot user-agent strings in HTTP headers can be blocked at WAF layer with minimal false positives.',        why:'Supplementary control: many bots don\'t spoof user agents, making UA blocking highly effective.' },
      { title:'Check C2 Indicators',         desc:`Verify ${dst} is not beaconing to known C2 infrastructure`,  dur:'5 min',   sev:'medium',   type:'manual', action:null,       detail:'Bot malware establishes C2 channels to receive instructions. Cross-check destination IPs against threat feeds.', why:'If the destination host is compromised, it requires immediate isolation to prevent data exfiltration.' },
      { title:'Generate Bot Report',         desc:'Document bot campaign pattern and all blocking actions taken', dur:'3 min',  sev:'low',      type:'auto',   action:'report',   detail:'Bot attack documentation enables tuning of detection rules and provides evidence for abuse reporting.',        why:'Bot campaigns repeat — detailed reports improve long-term detection accuracy.' },
    ],
    'XSS': [
      { title:'Block Source IP',             desc:`Add ${src} to firewall blocklist — XSS attack source`,       dur:'< 1 min', sev:'critical', type:'auto',   action:'blockIp',  detail:'Immediately stops further XSS payload delivery from this source IP.',                                       why:'Active XSS attacks steal session cookies and perform account takeover in real time — every second counts.' },
      { title:'Update WAF XSS Rules',        desc:'Enable XSS filter for detected payload signature in WAF',    dur:'2 min',   sev:'critical', type:'auto',   action:null,       detail:'WAF rules inspect HTTP request bodies and headers for XSS patterns (<script>, onerror=, javascript:, etc.).', why:'WAF blocks the payload even from different source IPs — essential when attackers rotate sources.' },
      { title:'Audit Affected Endpoints',    desc:`Review endpoints on ${dst} hit by XSS payload`,             dur:'10 min',  sev:'high',     type:'manual', action:null,       detail:'Identify whether the XSS was reflected (page render) or stored (database). Stored XSS affects all future visitors.', why:'Stored XSS persists indefinitely — it must be found in the database and sanitized at the root.' },
      { title:'Revoke Affected Sessions',    desc:'Invalidate sessions for users exposed to XSS payload',       dur:'3 min',   sev:'high',     type:'auto',   action:null,       detail:'If the XSS payload targeted session cookies, invalidate all sessions for potentially affected users.',            why:'Session hijacking via XSS lets the attacker impersonate users — all stolen sessions must be revoked.' },
      { title:'Patch Vulnerable Endpoint',   desc:'Apply HTML encoding and input sanitization to affected fields', dur:'15 min', sev:'medium',  type:'manual', action:null,       detail:'Fix the root cause: sanitize and encode all user-controlled input at the source (output encoding, CSP headers).', why:'WAF rules are temporary workarounds — a code-level fix is the only permanent solution.' },
      { title:'Generate Security Report',    desc:'Document XSS finding, payload, impact, and remediation',     dur:'5 min',   sev:'low',      type:'auto',   action:'report',   detail:'Security report documents the vulnerability, affected users, payload, and fix for compliance and disclosure.',    why:'GDPR may require breach notification if user session data was exposed via this XSS attack.' },
    ],
  };

  // Case-insensitive match against playbook keys
  const matchedKey = Object.keys(books).find(k => type.toLowerCase().includes(k.toLowerCase()));
  const raw = books[matchedKey] || [
    { title:'Block Source IP Address',     desc:`Add ${src} to firewall blocklist`,                            dur:'< 1 min', sev:'critical', type:'auto',   action:'blockIp',  detail:'Immediately stops traffic from the detected attack source at the network layer.',                            why:'First-response action to cut off the active attack while analysis proceeds.' },
    { title:'Update Security Rules',       desc:`Apply detection rules for ${type} attack pattern`,           dur:'2 min',   sev:'critical', type:'auto',   action:null,       detail:'Pattern-specific rules block the attack signature regardless of source IP rotation.',                         why:'IP blocks alone are insufficient if the attacker changes source addresses.' },
    { title:'Isolate Affected System',     desc:`Quarantine ${dst} pending investigation`,                    dur:'5 min',   sev:'high',     type:'manual', action:null,       detail:'Network isolation prevents lateral movement if the target system was compromised.',                           why:'Containment is critical until it is confirmed the attack did not succeed.' },
    { title:'Run Integrity Check',         desc:'Verify no data corruption or unauthorized changes',           dur:'10 min',  sev:'high',     type:'auto',   action:null,       detail:'Audit file hashes, database records, and configuration files for any tampering or exfiltration.',             why:'Establishes whether the attack caused any lasting impact requiring further remediation.' },
    { title:'Notify Security Team',        desc:'Send alert to on-call security analysts',                     dur:'< 1 min', sev:'medium',   type:'auto',   action:'notify',   detail:'Human review ensures appropriate escalation decisions and validates automated response actions.',               why:'AI detection is highly accurate, but human judgment is required for response scoping decisions.' },
    { title:'Generate Incident Report',    desc:'Create detailed report for compliance',                       dur:'3 min',   sev:'medium',   type:'auto',   action:'report',   detail:'Incident documentation is required for compliance frameworks (ISO 27001, SOC 2, GDPR, NCA-ECC).',            why:'Regulations may mandate incident documentation and notification within 24–72 hours of detection.' },
    { title:'Review Access Logs',          desc:'Manual review of authentication and access logs',             dur:'30 min',  sev:'low',      type:'manual', action:null,       detail:'Full log review reveals the complete attack chain and any previously undetected lateral movement.',            why:'Logs are the ground truth for understanding what happened and what data was accessed or modified.' },
  ];

  return raw.map((s, i) => ({ ...s, n: i + 1, status: 'pending' }));
}

// ===== State =====
let STEPS = buildPlaybook('default', '—', '—');
let alertData = null;

// ===== Render steps =====
function renderSteps() {
  const wrap = document.getElementById('stepsWrap');
  wrap.innerHTML = STEPS.map((s, i) => `
    <div class="step-card ${s.status}" data-n="${s.n}" style="animation-delay:${i * .06}s">
      <div class="step-num"><span>${s.n}</span></div>
      <div class="step-body">
        <div class="step-title">${s.title}</div>
        <div class="step-desc">${s.desc}</div>
        <div class="step-meta">
          <span><i class="fa-regular fa-clock"></i> ${s.dur}</span>
          <span>
            <i class="stat-dot ${s.status === 'done' ? 'done' : s.status === 'running' ? 'running' : ''}"></i>
            ${statusLabel(s.status)}
          </span>
        </div>
      </div>
      <div class="step-right">
        <div class="tag-group">
          <div class="step-tags">
            <span class="sev-chip ${s.sev}">${s.sev}</span>
            <span class="type-chip ${s.type}">${s.type}</span>
          </div>
        </div>
        <div class="step-actions">
          ${s.type === 'auto' && s.status !== 'done'
            ? `<button class="exec-btn" data-exec="${s.n}" ${s.status === 'running' ? 'disabled' : ''}>
                <i class="fa-solid fa-${s.status === 'running' ? 'spinner fa-spin' : 'play'}"></i>
                ${s.status === 'running' ? 'Running…' : 'Execute'}
               </button>`
            : ''}
          <button class="det-btn" data-det="${s.n}"><i class="fa-solid fa-circle-info"></i> Details</button>
        </div>
      </div>
    </div>
  `).join('');

  wrap.querySelectorAll('[data-exec]').forEach(b => {
    b.addEventListener('click', e => { e.stopPropagation(); executeStep(parseInt(b.dataset.exec)); });
  });
  wrap.querySelectorAll('[data-det]').forEach(b => {
    b.addEventListener('click', e => { e.stopPropagation(); showDetails(parseInt(b.dataset.det)); });
  });

  updateSidePanel();
}

function statusLabel(s) {
  if (s === 'done')    return 'Completed';
  if (s === 'running') return 'Running…';
  return 'Pending';
}

// ===== Execute single step =====
async function executeStep(n) {
  const step = STEPS.find(s => s.n === n);
  if (!step || step.status === 'done') return;
  step.status = 'running';
  renderSteps();
  showToast(`Executing: ${step.title}`);

  try {
    if (step.action === 'blockIp' && alertData?.source_ip && window.AisecAPI) {
      await AisecAPI.blockIp({
        ip: alertData.source_ip,
        reason: `[MADRS Auto-Response] ${step.title} — Alert #${alertData.id}`,
        severity: alertData.severity || 'HIGH',
        organizationId: alertData.organization_id || null,
      });
      showToast(`✓ ${alertData.source_ip} blocked in firewall`);
    } else if (step.action === 'notify') {
      showToast(`✓ Security team notified`);
    } else if (step.action === 'report') {
      showToast(`✓ Report queued for generation`);
    }
  } catch (err) {
    // Non-fatal — step is still marked done for demo/simulation
    console.warn('[response] execute action failed:', err.message);
  }

  await sleep(1600);
  step.status = 'done';
  renderSteps();
  showToast(`✓ ${step.title} completed`);

  const allDone = STEPS.every(s => s.status === 'done' || s.type === 'manual');
  if (allDone && alertData?.id && window.AisecAPI) {
    try { await AisecAPI.updateAlert(alertData.id, 'RESOLVED'); } catch { /* silent */ }
  }
}

// ===== Execute All Automated =====
const overlay  = document.getElementById('execOverlay');
const execBar  = document.getElementById('execBar');
const execStep = document.getElementById('execStep');
const execTitle = document.getElementById('execTitle');

document.getElementById('execAll').addEventListener('click', async () => {
  const autoSteps = STEPS.filter(s => s.type === 'auto' && s.status !== 'done');
  if (!autoSteps.length) { showToast('All automated steps already completed'); return; }

  execTitle.textContent = 'Executing Automated Playbook';
  overlay.classList.add('show');
  execBar.style.width = '0%';

  for (let i = 0; i < autoSteps.length; i++) {
    const s = autoSteps[i];
    execStep.textContent = `[${i + 1}/${autoSteps.length}] ${s.title}…`;
    s.status = 'running';
    renderSteps();

    try {
      if (s.action === 'blockIp' && alertData?.source_ip && window.AisecAPI) {
        await AisecAPI.blockIp({
          ip: alertData.source_ip,
          reason: `[MADRS Auto-Response] ${s.title} — Alert #${alertData.id}`,
          severity: alertData.severity || 'HIGH',
          organizationId: alertData.organization_id || null,
        });
      }
    } catch { /* non-fatal */ }

    await sleep(900);
    s.status = 'done';
    renderSteps();
    execBar.style.width = `${((i + 1) / autoSteps.length) * 100}%`;
    await sleep(300);
  }

  execStep.textContent = 'All automated steps completed ✓';
  await sleep(700);
  overlay.classList.remove('show');
  showToast(`${autoSteps.length} automated steps executed`);

  if (alertData?.id && window.AisecAPI) {
    try { await AisecAPI.updateAlert(alertData.id, 'RESOLVED'); } catch { /* silent */ }
  }
});

// ===== Dynamic side panel (timeline, impact, approvals) =====
function updateSidePanel() {
  renderTimeline();
  renderApprovals();
}

function parseDurMin(dur) {
  if (!dur || dur === '—') return 0;
  if (dur.includes('< 1')) return 0.5;
  const m = dur.match(/(\d+)/);
  return m ? parseInt(m[1]) : 1;
}

function renderTimeline() {
  const immediate  = STEPS.filter(s => parseDurMin(s.dur) <= 2);
  const shortTerm  = STEPS.filter(s => parseDurMin(s.dur) > 2 && parseDurMin(s.dur) <= 10);
  const followUp   = STEPS.filter(s => parseDurMin(s.dur) > 10);

  const el = document.querySelector('.exec-phase.green + .exec-phase.yellow')?.parentElement;
  const timelineEl = document.querySelector('.panel .exec-phase')?.closest('section');
  if (!timelineEl) return;

  timelineEl.querySelector('.exec-phase.green  .ep-desc').textContent =
    `Critical actions: ${immediate.length} step${immediate.length !== 1 ? 's' : ''}`;
  timelineEl.querySelector('.exec-phase.yellow .ep-desc').textContent =
    `High priority: ${shortTerm.length} step${shortTerm.length !== 1 ? 's' : ''}`;
  timelineEl.querySelector('.exec-phase.blue   .ep-desc').textContent =
    `Medium/Low priority: ${followUp.length} step${followUp.length !== 1 ? 's' : ''}`;
}

function renderApprovals() {
  const appSection = document.querySelector('.approvals');
  if (!appSection) return;

  const manualSteps = STEPS.filter(s => s.type === 'manual');
  const autoSteps   = STEPS.filter(s => s.type === 'auto');

  if (!manualSteps.length) {
    appSection.innerHTML = `<div class="app-row approved"><span>All Steps</span><i class="fa-solid fa-circle-check"></i></div>`;
    return;
  }

  const autoNums   = autoSteps.map(s => s.n);
  const manualNums = manualSteps.map(s => s.n);

  const autoRange   = rangeLabel(autoNums);
  const manualRange = rangeLabel(manualNums);

  appSection.innerHTML = `
    <div class="app-row approved">
      <span>Steps ${autoRange} (automated)</span>
      <i class="fa-solid fa-circle-check"></i>
    </div>
    <div class="app-row pending">
      <span>Steps ${manualRange} (manual)</span>
      <span>Pending Admin</span>
    </div>
  `;
}

function rangeLabel(nums) {
  if (!nums.length) return '—';
  if (nums.length === 1) return String(nums[0]);
  // Build compact ranges like "1, 3-5, 7"
  const sorted = [...nums].sort((a, b) => a - b);
  const ranges = [];
  let start = sorted[0], end = sorted[0];
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i] === end + 1) { end = sorted[i]; }
    else { ranges.push(start === end ? String(start) : `${start}-${end}`); start = end = sorted[i]; }
  }
  ranges.push(start === end ? String(start) : `${start}-${end}`);
  return ranges.join(', ');
}

// ===== Stats counters =====
function animateCounter(el, target) {
  const dur = 900, t0 = performance.now();
  (function tick(now) {
    const p = Math.min((now - t0) / dur, 1);
    const e = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(target * e);
    if (p < 1) requestAnimationFrame(tick);
  })(performance.now());
}

function updateStats() {
  const totalEl  = document.querySelector('.ss-val[data-target]');
  const autoEl   = document.querySelectorAll('.ss-val[data-target]')[1];
  const manualEl = document.querySelectorAll('.ss-val[data-target]')[2];
  const timeSpan = document.querySelector('.ss-val.green span[data-target]');

  const total    = STEPS.length;
  const autoN    = STEPS.filter(s => s.type === 'auto').length;
  const manualN  = STEPS.filter(s => s.type === 'manual').length;
  const totalMin = Math.ceil(STEPS.reduce((acc, s) => acc + parseDurMin(s.dur), 0));

  if (totalEl)  animateCounter(totalEl,  total);
  if (autoEl)   animateCounter(autoEl,   autoN);
  if (manualEl) animateCounter(manualEl, manualN);
  if (timeSpan) animateCounter(timeSpan, totalMin);
}

// ===== Impact bars =====
function updateImpact(attackType, sev) {
  const t = (attackType || '').toLowerCase();
  const s = (sev || '').toLowerCase();

  let sd, dr, re;

  if (t.includes('ddos') || t.includes('dos')) {
    sd = s === 'critical' ? 90 : 70;
    dr = s === 'critical' ? 45 : 30;
    re = 80;
  } else if (t.includes('brute') || t.includes('xss') || t.includes('web')) {
    sd = 20;
    dr = s === 'critical' ? 95 : 80;
    re = 88;
  } else if (t.includes('scan') || t.includes('recon')) {
    sd = 5;
    dr = 25;
    re = 95;
  } else if (t.includes('bot')) {
    sd = 35;
    dr = 60;
    re = 82;
  } else {
    sd = s === 'critical' ? 35 : s === 'high' ? 25 : 15;
    dr = s === 'critical' ? 90 : s === 'high' ? 75 : 55;
    re = s === 'critical' ? 90 : 80;
  }

  const sdLbl = sd > 60 ? 'High' : sd > 30 ? 'Medium' : 'Low';
  const drLbl = dr > 60 ? 'High' : dr > 30 ? 'Medium' : 'Low';
  const reLbl = re > 70 ? 'High' : 'Medium';

  const sdCls = sdLbl === 'High' ? 'high' : sdLbl === 'Medium' ? 'medium' : 'low';
  const drCls = drLbl === 'High' ? 'high' : 'medium';

  document.querySelector('.ia-head:nth-child(1) .ia-lbl') && (() => {
    const heads = document.querySelectorAll('.ia-head');
    if (heads[0]) heads[0].querySelector('.ia-lbl').className = `ia-lbl ${sdCls}`;
    if (heads[0]) heads[0].querySelector('.ia-lbl').textContent = sdLbl;
    if (heads[1]) heads[1].querySelector('.ia-lbl').className = `ia-lbl ${drCls}`;
    if (heads[1]) heads[1].querySelector('.ia-lbl').textContent = drLbl;
    if (heads[2]) heads[2].querySelector('.ia-lbl').className = 'ia-lbl high';
    if (heads[2]) heads[2].querySelector('.ia-lbl').textContent = reLbl;
  })();

  setTimeout(() => {
    const barSd = document.getElementById('barSd');
    const barDr = document.getElementById('barDr');
    const barRe = document.getElementById('barRe');
    if (barSd) barSd.style.width = sd + '%';
    if (barDr) barDr.style.width = dr + '%';
    if (barRe) barRe.style.width = re + '%';
  }, 400);
}

// ===== Details modal =====
const detailsModal = document.createElement('div');
detailsModal.className = 'deep-overlay';
detailsModal.innerHTML = `
  <div class="deep-card resp-detail-card">
    <div class="resp-detail-header">
      <div>
        <div id="detTitle" style="font-size:17px;font-weight:700;margin-bottom:4px"></div>
        <div id="detMeta" style="font-size:12px;color:var(--muted);display:flex;gap:10px;flex-wrap:wrap"></div>
      </div>
      <button class="det-close-btn" id="detClose"><i class="fa-solid fa-xmark"></i></button>
    </div>
    <div class="resp-detail-body">
      <div class="resp-det-section">
        <div class="resp-det-label"><i class="fa-solid fa-circle-info"></i> What this step does</div>
        <div id="detDetail" class="resp-det-text"></div>
      </div>
      <div class="resp-det-section">
        <div class="resp-det-label"><i class="fa-solid fa-lightbulb"></i> Why it matters</div>
        <div id="detWhy" class="resp-det-text"></div>
      </div>
      <div class="resp-det-section">
        <div class="resp-det-label"><i class="fa-solid fa-file-lines"></i> Description</div>
        <div id="detDesc" class="resp-det-text"></div>
      </div>
    </div>
    <div style="display:flex;justify-content:flex-end;margin-top:20px">
      <button class="ns-btn cyan" id="detExec" style="display:none"><i class="fa-solid fa-play"></i> Execute Now</button>
      <button class="ns-btn dark" id="detCloseBtn" style="margin-left:10px">Close</button>
    </div>
  </div>
`;
document.body.appendChild(detailsModal);

document.getElementById('detClose').addEventListener('click',    () => detailsModal.classList.remove('show'));
document.getElementById('detCloseBtn').addEventListener('click', () => detailsModal.classList.remove('show'));
detailsModal.addEventListener('click', e => { if (e.target === detailsModal) detailsModal.classList.remove('show'); });

function showDetails(n) {
  const step = STEPS.find(s => s.n === n);
  if (!step) return;

  document.getElementById('detTitle').textContent  = `Step ${step.n}: ${step.title}`;
  document.getElementById('detDetail').textContent = step.detail || step.desc;
  document.getElementById('detWhy').textContent    = step.why    || '—';
  document.getElementById('detDesc').textContent   = step.desc;
  document.getElementById('detMeta').innerHTML = `
    <span><i class="fa-regular fa-clock"></i> ${step.dur}</span>
    <span class="sev-chip ${step.sev}" style="font-size:11px">${step.sev}</span>
    <span class="type-chip ${step.type}" style="font-size:11px">${step.type}</span>
    <span style="color:${step.status === 'done' ? '#51cf66' : '#ffd43b'}">${statusLabel(step.status)}</span>
  `;

  const execBtn = document.getElementById('detExec');
  if (step.type === 'auto' && step.status !== 'done') {
    execBtn.style.display = '';
    execBtn.onclick = () => { detailsModal.classList.remove('show'); executeStep(n); };
  } else {
    execBtn.style.display = 'none';
  }

  detailsModal.classList.add('show');
}

// ===== Approve All =====
document.getElementById('approveAll').addEventListener('click', () => {
  document.querySelectorAll('.app-row').forEach(r => {
    r.classList.remove('pending', 'notreq');
    r.classList.add('approved');
    const span = r.querySelector('span:last-child');
    if (span && span !== r.querySelector('span:first-child')) span.remove();
    if (!r.querySelector('i')) {
      const ic = document.createElement('i');
      ic.className = 'fa-solid fa-circle-check';
      r.appendChild(ic);
    }
  });
  showToast('All approvals granted');
});

// ===== Schedule Execution modal =====
const scheduleModal = document.createElement('div');
scheduleModal.className = 'deep-overlay';
scheduleModal.innerHTML = `
  <div class="deep-card">
    <h2>Schedule Execution</h2>
    <p class="muted">Select a start time for remaining manual steps.</p>
    <label class="muted" style="display:block;margin:12px 0 6px">Start Time</label>
    <input type="datetime-local" id="scheduleTime" class="input">
    <div style="display:flex;gap:10px;margin-top:18px;justify-content:flex-end">
      <button class="btn btn-ghost" id="cancelSchedule">Cancel</button>
      <button class="btn btn-primary" id="confirmSchedule">Confirm</button>
    </div>
  </div>`;
document.body.appendChild(scheduleModal);

document.getElementById('scheduleExec').addEventListener('click', () => scheduleModal.classList.add('show'));
scheduleModal.addEventListener('click', e => {
  if (e.target === scheduleModal || e.target.id === 'cancelSchedule') scheduleModal.classList.remove('show');
});
scheduleModal.querySelector('#confirmSchedule').addEventListener('click', () => {
  const dt = scheduleModal.querySelector('#scheduleTime').value;
  scheduleModal.classList.remove('show');
  showToast(dt ? `Scheduled for ${new Date(dt).toLocaleString()}` : 'Execution scheduled');
});

// ===== Export Plan =====
const exportBtn = document.getElementById('exportPlan');
if (exportBtn) {
  exportBtn.addEventListener('click', async () => {
    if (!window.AisecAPI) { showToast('API unavailable'); return; }
    const m = rawId.match(/(\d+)/);
    const alertId = m ? parseInt(m[1]) : null;
    if (!alertId) { showToast('Unable to determine incident ID'); return; }
    try {
      const { name } = await AisecAPI.downloadResponsePlan(alertId);
      showToast(`Downloaded: ${name}`);
    } catch (err) {
      showToast(err?.status === 401 ? 'Session expired — please log in again' : 'Export failed: ' + (err?.message || 'unknown'));
    }
  });
}

// ===== Toast =====
const toast = document.getElementById('toast');
function showToast(msg, isError) {
  toast.querySelector('span').textContent = msg;
  toast.style.background = isError ? '#ff6b6b' : '';
  toast.classList.add('show');
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.remove('show'), 2200);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ===== Initial render with default playbook =====
renderSteps();
updateStats();
updateImpact('default', 'high');

// ===== Load real alert data from backend =====
(async function loadFromAlert() {
  if (!window.AisecAPI) return;
  const m = rawId.match(/(\d+)/);
  if (!m) return;
  const numId = parseInt(m[1]);

  try {
    const a = await AisecAPI.getAlert(numId);
    alertData = a;

    const idStr  = 'INC-' + String(a.id).padStart(3, '0');
    const type   = a.attack_type || 'Unknown';
    const sev    = (a.severity   || 'MEDIUM').toLowerCase();
    const srcIp  = a.source_ip   || '—';
    const dstIp  = a.dest_ip     || '—';

    document.getElementById('incRef').textContent = idStr;
    document.getElementById('backLink').href = 'incident.html?id=' + a.id;
    document.getElementById('backBtn2').onclick = () => window.location.href = 'incident.html?id=' + a.id;
    document.title = `${idStr} — Response Plan`;

    STEPS = buildPlaybook(type, srcIp, dstIp);
    renderSteps();
    updateStats();
    updateImpact(type, sev);
  } catch (err) {
    console.warn('[response] backend load failed, using defaults:', err.message);
  }
})();
