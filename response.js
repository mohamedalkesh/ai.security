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
document.getElementById('backBtn2').addEventListener('click', () => window.location.href = 'incident.html?id=' + id);
document.title = `${id} — Response Plan`;

// Animate stat numbers
document.querySelectorAll('[data-target]').forEach(el => {
  const target = parseInt(el.dataset.target);
  const dur = 1200, start = performance.now();
  (function tick(now){
    const p = Math.min((now-start)/dur, 1);
    const e = 1 - Math.pow(1-p, 3);
    el.textContent = Math.floor(target * e);
    if (p<1) requestAnimationFrame(tick);
  })(performance.now());
});

// ===== Steps =====
const STEPS = [
  { n:1, title:'Block Source IP Address', desc:'Add 192.168.1.45 to firewall blocklist',       dur:'< 1 min', sev:'critical', type:'auto',   status:'pending' },
  { n:2, title:'Update WAF Rules',         desc:'Add SQL injection pattern to Web Application Firewall', dur:'2 min', sev:'critical', type:'auto',   status:'pending' },
  { n:3, title:'Isolate Affected System',  desc:'Quarantine database server from network',     dur:'5 min', sev:'high',    type:'manual', status:'pending' },
  { n:4, title:'Run Database Integrity Check', desc:'Verify no data corruption or unauthorized changes', dur:'10 min', sev:'high', type:'auto', status:'pending' },
  { n:5, title:'Notify Security Team',     desc:'Send alert to on-call security analysts',     dur:'< 1 min', sev:'medium', type:'auto',   status:'pending' },
  { n:6, title:'Generate Incident Report', desc:'Create detailed report for compliance',        dur:'3 min', sev:'medium',  type:'auto',   status:'pending' },
  { n:7, title:'Review Access Logs',       desc:'Manual review of authentication logs',        dur:'30 min', sev:'low',     type:'manual', status:'pending' },
];

function renderSteps(){
  const wrap = document.getElementById('stepsWrap');
  wrap.innerHTML = STEPS.map((s, i) => `
    <div class="step-card ${s.status}" data-n="${s.n}" style="animation-delay:${i*.07}s">
      <div class="step-num"><span>${s.n}</span></div>
      <div class="step-body">
        <div class="step-title">${s.title}</div>
        <div class="step-desc">${s.desc}</div>
        <div class="step-meta">
          <span><i class="fa-regular fa-clock"></i> ${s.dur}</span>
          <span><i class="stat-dot ${s.status==='done'?'done':s.status==='running'?'running':''}"></i> ${statusLabel(s.status)}</span>
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
          ${s.type==='auto' && s.status!=='done' ? `<button class="exec-btn" data-exec="${s.n}" ${s.status==='running'?'disabled':''}><i class="fa-solid fa-play"></i> ${s.status==='running'?'Running':'Execute'}</button>` : ''}
          <button class="det-btn">Details</button>
        </div>
      </div>
    </div>
  `).join('');

  wrap.querySelectorAll('[data-exec]').forEach(b => {
    b.addEventListener('click', (e) => {
      e.stopPropagation();
      executeStep(parseInt(b.dataset.exec));
    });
  });
}
function statusLabel(s){
  if (s==='done') return 'Completed';
  if (s==='running') return 'Running...';
  return 'Pending';
}
renderSteps();

// Execute single step
function executeStep(n){
  const step = STEPS.find(s => s.n === n);
  if (!step || step.status === 'done') return;
  step.status = 'running';
  renderSteps();
  showToast(`Executing: ${step.title}`);
  setTimeout(() => {
    step.status = 'done';
    renderSteps();
    showToast(`✓ ${step.title} completed`);
  }, 1800);
}

// ===== Execute All Automated (overlay flow) =====
const overlay = document.getElementById('execOverlay');
const execBar = document.getElementById('execBar');
const execStep = document.getElementById('execStep');
const execTitle = document.getElementById('execTitle');

document.getElementById('execAll').addEventListener('click', async () => {
  const autoSteps = STEPS.filter(s => s.type === 'auto' && s.status !== 'done');
  if (!autoSteps.length){ showToast('All automated steps already completed'); return; }

  execTitle.textContent = 'Executing Automated Steps';
  overlay.classList.add('show');
  execBar.style.width = '0%';

  for (let i = 0; i < autoSteps.length; i++){
    const s = autoSteps[i];
    execStep.textContent = `[${i+1}/${autoSteps.length}] ${s.title}...`;
    s.status = 'running';
    renderSteps();
    await sleep(900);
    s.status = 'done';
    renderSteps();
    execBar.style.width = (((i+1)/autoSteps.length)*100) + '%';
    await sleep(300);
  }

  execStep.textContent = 'All automated steps completed ✓';
  await sleep(700);
  overlay.classList.remove('show');
  showToast(`${autoSteps.length} automated steps executed`);
});

function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }

// ===== Impact bars =====
setTimeout(() => {
  document.getElementById('barSd').style.width = '30%';
  document.getElementById('barDr').style.width = '85%';
  document.getElementById('barRe').style.width = '90%';
}, 400);

// Approve All
document.getElementById('approveAll').addEventListener('click', () => {
  document.querySelectorAll('.app-row').forEach(r => {
    r.classList.remove('pending','notreq');
    r.classList.add('approved');
    if (!r.querySelector('i')){
      const i = document.createElement('i');
      i.className = 'fa-solid fa-circle-check';
      const second = r.children[1];
      if (second && second.tagName === 'SPAN') second.remove();
      r.appendChild(i);
    }
  });
  showToast('All approvals granted');
});

// Toast
const toast = document.getElementById('toast');
function showToast(msg){
  toast.querySelector('span').textContent = msg;
  toast.classList.add('show');
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.remove('show'), 1800);
}

// Other actions
document.querySelectorAll('.det-btn').forEach(b => {
  b.addEventListener('click', (e) => {
    e.stopPropagation();
    showToast(b.textContent.trim() + ' triggered');
  });
});

const scheduleBtn = document.getElementById('scheduleExec');
if (scheduleBtn) {
  const scheduleModal = document.createElement('div');
  scheduleModal.className = 'deep-overlay';
  scheduleModal.innerHTML = `
    <div class="deep-card">
      <h2>Schedule Execution</h2>
      <p class="muted">Select a start time to execute the remaining manual steps.</p>
      <label class="muted" style="display:block;margin:12px 0 6px">Start Time</label>
      <input type="datetime-local" id="scheduleTime" class="input">
      <div style="display:flex;gap:10px;margin-top:18px;justify-content:flex-end">
        <button class="btn btn-ghost" id="cancelSchedule">Cancel</button>
        <button class="btn btn-primary" id="confirmSchedule">Confirm</button>
      </div>
    </div>`;
  document.body.appendChild(scheduleModal);

  scheduleBtn.addEventListener('click', () => {
    scheduleModal.classList.add('show');
  });

  scheduleModal.addEventListener('click', (e) => {
    if (e.target === scheduleModal || e.target.id === 'cancelSchedule') {
      scheduleModal.classList.remove('show');
    }
  });
  scheduleModal.querySelector('#confirmSchedule').addEventListener('click', () => {
    const dt = scheduleModal.querySelector('#scheduleTime').value;
    scheduleModal.classList.remove('show');
    showToast(dt ? `Execution scheduled for ${new Date(dt).toLocaleString()}` : 'Execution scheduled');
  });
}

const exportBtn = document.getElementById('exportPlan');
if (exportBtn) {
  exportBtn.addEventListener('click', async () => {
    if (!window.AisecAPI) { showToast('API unavailable'); return; }
    const m = id.match(/(\d+)/);
    const alertId = m ? parseInt(m[1]) : null;
    if (!alertId) { showToast('Unable to determine incident'); return; }
    try {
      const { name } = await AisecAPI.downloadResponsePlan(alertId);
      showToast(`Response plan downloaded: ${name}`);
    } catch (err) {
      const msg = err?.status === 401 ? 'Session expired — please log in again' : 'Download failed: ' + (err?.message || 'unknown error');
      showToast(msg);
    }
  });
}

// ===== Backend integration: generate response plan from real alert =====
(async function loadFromBackend(){
  if (!window.AisecAPI) return;
  const raw = params.get('id') || '';
  const m = raw.match(/(\d+)/);
  if (!m) return;
  const numId = parseInt(m[1]);

  try {
    const a = await AisecAPI.getAlert(numId);
    const idStr = 'INC-' + String(a.id).padStart(3, '0');
    const type = a.attack_type || 'Unknown';
    const sev = (a.severity || 'MEDIUM').toLowerCase();
    const srcIp = a.source_ip || '—';
    const dstIp = a.dest_ip || '—';

    // Update header
    document.getElementById('incRef').textContent = idStr;
    document.getElementById('backLink').href = 'incident.html?id=' + a.id;
    document.title = `${idStr} — Response Plan`;

    // Generate context-aware response steps based on attack type
    const stepTemplates = {
      'DDoS':         [
        { title:'Enable DDoS Mitigation',       desc:`Activate rate limiting for traffic from ${srcIp}`,        dur:'< 1 min', sev:'critical', type:'auto' },
        { title:'Scale Edge Capacity',           desc:'Auto-scale edge nodes to absorb flood',                   dur:'2 min',   sev:'critical', type:'auto' },
        { title:'Block Source Ranges',           desc:`Add ${srcIp}/24 to upstream blackhole`,                   dur:'1 min',   sev:'high',     type:'auto' },
        { title:'Enable Traffic Scrubbing',      desc:'Route inbound traffic through scrubbing center',          dur:'5 min',   sev:'high',     type:'manual' },
        { title:'Notify NOC Team',               desc:'Alert Network Operations Center of ongoing attack',       dur:'< 1 min', sev:'medium',   type:'auto' },
        { title:'Generate Post-Incident Report', desc:'Document attack timeline and countermeasures',            dur:'10 min',  sev:'low',      type:'auto' },
      ],
      'Brute Force':  [
        { title:'Block Source IP',               desc:`Add ${srcIp} to firewall blocklist`,                     dur:'< 1 min', sev:'critical', type:'auto' },
        { title:'Lock Targeted Accounts',        desc:'Temporarily lock accounts with failed attempts',          dur:'1 min',   sev:'critical', type:'auto' },
        { title:'Enable CAPTCHA / MFA',          desc:'Enforce multi-factor authentication for affected service', dur:'5 min',   sev:'high',     type:'manual' },
        { title:'Review Authentication Logs',    desc:'Identify all affected accounts and sessions',             dur:'15 min',  sev:'high',     type:'manual' },
        { title:'Reset Compromised Credentials', desc:'Force password reset for any breached accounts',          dur:'5 min',   sev:'medium',   type:'auto' },
        { title:'Generate Compliance Report',    desc:'Document incident for regulatory compliance',             dur:'10 min',  sev:'low',      type:'auto' },
      ],
      'default':      [
        { title:'Block Source IP Address',       desc:`Add ${srcIp} to firewall blocklist`,                     dur:'< 1 min', sev:'critical', type:'auto' },
        { title:'Update Security Rules',         desc:`Add ${type} pattern to defense rules`,                   dur:'2 min',   sev:'critical', type:'auto' },
        { title:'Isolate Affected System',       desc:`Quarantine ${dstIp} from network`,                       dur:'5 min',   sev:'high',     type:'manual' },
        { title:'Run Integrity Check',           desc:'Verify no data corruption or unauthorized changes',      dur:'10 min',  sev:'high',     type:'auto' },
        { title:'Notify Security Team',          desc:'Send alert to on-call security analysts',                dur:'< 1 min', sev:'medium',   type:'auto' },
        { title:'Generate Incident Report',      desc:'Create detailed report for compliance',                  dur:'3 min',   sev:'medium',   type:'auto' },
        { title:'Review Access Logs',            desc:'Manual review of authentication and access logs',        dur:'30 min',  sev:'low',      type:'manual' },
      ],
    };

    const matchedKey = Object.keys(stepTemplates).find(k => k !== 'default' && type.toLowerCase().includes(k.toLowerCase()));
    const stepsTemplate = stepTemplates[matchedKey] || stepTemplates['default'];

    // Overwrite STEPS array (it's used by renderSteps and executeStep above)
    STEPS.length = 0;
    stepsTemplate.forEach((s, i) => {
      STEPS.push({ n: i + 1, title: s.title, desc: s.desc, dur: s.dur, sev: s.sev, type: s.type, status: 'pending' });
    });
    renderSteps();

    // Update stat counters
    const statEls = document.querySelectorAll('[data-target]');
    if (statEls[0]) { statEls[0].dataset.target = STEPS.length; statEls[0].textContent = STEPS.length; }
    const autoCount = STEPS.filter(s => s.type === 'auto').length;
    if (statEls[1]) { statEls[1].dataset.target = autoCount; statEls[1].textContent = autoCount; }

    // Impact bars from severity
    const sdPct = sev === 'critical' ? 15 : sev === 'high' ? 30 : 50;
    const drPct = sev === 'critical' ? 95 : sev === 'high' ? 80 : 60;
    const rePct = sev === 'critical' ? 95 : sev === 'high' ? 85 : 70;
    document.getElementById('barSd').style.width = sdPct + '%';
    document.getElementById('barDr').style.width = drPct + '%';
    document.getElementById('barRe').style.width = rePct + '%';

    // Wire Respond button to update backend alert status
    const respondBtn = document.getElementById('execAll');
    if (respondBtn) {
      const origClick = respondBtn.onclick;
      respondBtn.addEventListener('click', async () => {
        try {
          await AisecAPI.updateAlert(a.id, 'RESOLVED');
        } catch { /* ignore, exec animation handles UI */ }
      }, { once: true });
    }

  } catch (err) {
    console.warn('[response] backend load failed, using static data:', err.message);
  }
})();
