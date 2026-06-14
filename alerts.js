function renderExplanation(raw) {
  const block = document.getElementById('mExplainBlock');
  const summary = document.getElementById('mExplainSummary');
  const list = document.getElementById('mExplainTop');
  const details = document.getElementById('mExplainDetails');
  const payloadBox = document.getElementById('mExplainPayload');
  const payloadAscii = document.getElementById('mExplainPayloadAscii');
  const payloadHex = document.getElementById('mExplainPayloadHex');
  const payloadMeta = document.getElementById('mExplainPayloadMeta');
  const payloadNote = document.getElementById('mExplainPayloadNote');
  if (!block || !summary || !list || !details || !payloadBox || !payloadAscii || !payloadHex || !payloadMeta || !payloadNote) return;
  if (!raw) {
    block.style.display = 'none';
    summary.textContent = '—';
    list.innerHTML = '';
    details.innerHTML = '';
    payloadBox.style.display = 'none';
    return;
  }
  try {
    const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
    summary.textContent = parsed.summary || 'Model-provided reasoning unavailable';

    const narrative = Array.isArray(parsed.details) ? parsed.details : [];
    details.innerHTML = narrative.map(line => `<li>${line}</li>`).join('');
    details.style.display = narrative.length ? 'flex' : 'none';

    const sample = parsed.payload_sample;
    if (sample && (sample.ascii || sample.hex)) {
      payloadAscii.textContent = sample.ascii || '—';
      payloadHex.textContent = sample.hex ? sample.hex.match(/.{1,32}/g)?.join('\n') : '—';
      const size = sample.preview_bytes ?? sample.size_bytes;
      payloadMeta.textContent = size ? `${size} bytes preview` : '';
      payloadNote.textContent = sample.note || '';
      payloadBox.style.display = '';
    } else {
      payloadBox.style.display = 'none';
    }

    const top = parsed.top_features || [];
    list.innerHTML = top.map((f) => `
      <div class="muted sm" style="display:flex;justify-content:space-between;gap:8px;padding:6px 10px;background:#0b1628;border:1px solid #1e3557;border-radius:8px">
        <span style="font-weight:600;color:#e2e8f0">${f.feature}</span>
        <span class="mono">${f.value ?? '—'} (${f.impact > 0 ? '+' : ''}${(f.impact ?? 0).toFixed ? f.impact.toFixed(3) : f.impact})</span>
      </div>
    `).join('');

    block.style.display = '';
  } catch (e) {
    block.style.display = 'none';
  }
}
// ===== Reveal animations =====
const io = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting){ e.target.classList.add('visible'); io.unobserve(e.target); }});
}, { threshold:.1 });
document.querySelectorAll('.reveal').forEach(el => io.observe(el));

// Require auth
if (window.AisecAPI) AisecAPI.requireAuth();

// ===== Mappings =====
const ICONS = {
  'DDoS': 'fa-bolt',
  'Port Scan': 'fa-network-wired',
  'Brute Force': 'fa-key',
  'SQL Injection': 'fa-database',
  'XSS': 'fa-code',
  'Malware': 'fa-virus',
  'Phishing': 'fa-fishing-rod',
  'Reconnaissance': 'fa-magnifying-glass',
  'Unknown': 'fa-circle-question'
};
function iconFor(type) {
  if (!type) return 'fa-triangle-exclamation';
  for (const k in ICONS) if (type.toLowerCase().includes(k.toLowerCase())) return ICONS[k];
  return 'fa-triangle-exclamation';
}

const SEV_ORDER = { CRITICAL:5, HIGH:4, MEDIUM:3, LOW:2, INFORMATIONAL:1 };

function timeAgo(iso) {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  const diff = (Date.now() - t) / 1000;
  if (diff < 60)    return Math.floor(diff) + ' sec ago';
  if (diff < 3600)  return Math.floor(diff/60) + ' min ago';
  if (diff < 86400) return Math.floor(diff/3600) + ' hour ago';
  return Math.floor(diff/86400) + ' day ago';
}

/** ISO-2 country code → flag emoji (Unicode regional indicators). */
function flagEmoji(cc) {
  if (!cc || cc.length !== 2) return '';
  const A = 0x1F1E6, off = cc.toUpperCase().charCodeAt(0) - 65;
  const B = cc.toUpperCase().charCodeAt(1) - 65;
  if (off < 0 || off > 25 || B < 0 || B > 25) return '';
  return String.fromCodePoint(A + off) + String.fromCodePoint(A + B);
}

// ===== State =====
let alertsData = [];
let usersData  = [];                 // for the assignee dropdown
const selectedIds = new Set();       // for bulk actions
// Pick up a one-shot search hint stashed by incidents.js (drill-down).
const _initialSearch = sessionStorage.getItem('alerts_search') || '';
if (_initialSearch) sessionStorage.removeItem('alerts_search');
let state = { search:_initialSearch, sev:'', sort:'sev', page:1, perPage:25 };

const body = document.getElementById('alertsBody');
const pageInfo = document.getElementById('pageInfo');
const pager = document.getElementById('pager');
const autoResolveBtn = document.getElementById('autoResolveBtn');
const autoModal = document.getElementById('autoResolveModal');
const autoMaxSeverity = document.getElementById('autoMaxSeverity');
const autoMinConfidence = document.getElementById('autoMinConfidence');
const autoLimit = document.getElementById('autoLimit');
const autoReason = document.getElementById('autoReason');
const autoPreview = document.getElementById('autoPreview');

// ===== Loader / status =====
function setStatusBanner(text, kind) {
  let bar = document.getElementById('alertsBanner');
  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'alertsBanner';
    bar.style.cssText = 'padding:10px 14px;border-radius:8px;margin:0 0 14px;font-size:13px;font-weight:500';
    document.querySelector('.alerts-toolbar')?.before(bar);
  }
  if (!text) { bar.style.display = 'none'; return; }
  bar.style.display = 'block';
  const colors = {
    info:    'background:rgba(34,184,207,.15);border:1px solid rgba(34,184,207,.4);color:#a5f3fc',
    error:   'background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.4);color:#fecaca',
    success: 'background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.4);color:#bbf7d0'
  };
  bar.style.cssText = 'padding:10px 14px;border-radius:8px;margin:0 0 14px;font-size:13px;font-weight:500;' + (colors[kind] || colors.info);
  bar.textContent = text;
}

// ===== Render =====
function render(){
  let rows = alertsData.filter(a => {
    const q = state.search.toLowerCase();
    const matchQ = !q ||
      String(a.id).includes(q) ||
      (a.attack_type || '').toLowerCase().includes(q) ||
      (a.source_ip || '').includes(q) ||
      (a.dest_ip || '').includes(q);
    const matchS = !state.sev || (a.severity || '').toLowerCase() === state.sev.toLowerCase();
    return matchQ && matchS;
  });
  if (state.sort === 'sev') rows.sort((a,b) => ((SEV_ORDER[b.severity]||0) - (SEV_ORDER[a.severity]||0)) || (new Date(b.created_at) - new Date(a.created_at)));
  else if (state.sort === 'id') rows.sort((a,b) => a.id - b.id);
  else rows.sort((a,b) => new Date(b.created_at) - new Date(a.created_at));

  const total = rows.length;
  const start = (state.page - 1) * state.perPage;
  const pageRows = rows.slice(start, start + state.perPage);

  body.innerHTML = pageRows.map((a, i) => {
    const flag = flagEmoji(a.src_country);
    const fbIco = a.ml_feedback === 'TRUE_POSITIVE' ? '<i class="fa-solid fa-thumbs-up" style="color:#22c55e" title="Confirmed attack"></i> ' :
                  a.ml_feedback === 'FALSE_POSITIVE' ? '<i class="fa-solid fa-thumbs-down" style="color:#ef4444" title="False positive"></i> ' : '';
    const assignee = a.assigned_to_username
        ? `<span class="status-pill" style="background:rgba(34,184,207,.15);color:#a5f3fc"><i class="fa-solid fa-user"></i> ${a.assigned_to_username}</span>`
        : `<span class="muted sm">—</span>`;
    return `
    <tr style="animation-delay:${i*40}ms" data-id="${a.id}">
      <td><input type="checkbox" class="alert-check" data-id="${a.id}" ${selectedIds.has(a.id)?'checked':''}/></td>
      <td class="cell-id">INC-${String(a.id).padStart(3,'0')}</td>
      <td>${fbIco}<div class="cell-type" style="display:inline-flex"><span class="t-ico"><i class="fa-solid ${iconFor(a.attack_type)}"></i></span>${a.attack_type || 'Unknown'}</div></td>
      <td><span class="badge-sev ${(a.severity || '').toLowerCase()}">${a.severity || '—'}</span></td>
      <td class="cell-ip">${flag ? flag + ' ' : ''}${a.source_ip || '—'}</td>
      <td><span class="status-pill ${(a.status || '').toLowerCase()}">${(a.status || '').toLowerCase().replace('_',' ')}</span></td>
      <td>${assignee}</td>
      <td class="cell-time"><i class="fa-regular fa-clock"></i> ${timeAgo(a.created_at)}</td>
      <td class="right"><a class="view-btn" href="incident.html?id=${a.id}"><i class="fa-regular fa-eye"></i> View</a></td>
    </tr>`;
  }).join('') || `<tr><td colspan="9" style="text-align:center;padding:40px;color:var(--muted)">No alerts match your filters.</td></tr>`;

  pageInfo.textContent = total ? `Showing ${start+1}-${Math.min(start+state.perPage,total)} of ${total} alerts` : 'No results';

  const totalPages = Math.max(1, Math.ceil(total / state.perPage));
  let html = `<button class="nav-btn" ${state.page===1?'disabled':''} data-go="prev">Previous</button>`;
  const startPage = Math.max(1, Math.min(state.page - 2, totalPages - 4));
  for (let i = startPage; i <= Math.min(startPage + 4, totalPages); i++){
    html += `<button class="${i===state.page?'active':''}" data-go="${i}">${i}</button>`;
  }
  html += `<button class="nav-btn" ${state.page===totalPages?'disabled':''} data-go="next">Next</button>`;
  pager.innerHTML = html;

  // Row click -> open modal (but not when clicking the View link or checkbox)
  body.querySelectorAll('tr[data-id]').forEach(tr => {
    tr.addEventListener('click', (e) => {
      if (e.target.closest('.view-btn') || e.target.closest('.alert-check')) return;
      openModal(parseInt(tr.dataset.id));
    });
  });

  // Re-apply role gating (new buttons just got rendered).
  if (window.AisecAPI && AisecAPI.applyRbac) AisecAPI.applyRbac();
  updateBulkBar();
}

// ===== Bulk selection =====
const bulkBar = document.getElementById('bulkBar');
const bulkCount = document.getElementById('bulkCount');
const selectAllCb = document.getElementById('selectAll');

function updateBulkBar() {
  const n = selectedIds.size;
  bulkBar.style.display = n > 0 ? 'flex' : 'none';
  bulkCount.textContent = String(n);
  // Refresh select-all checkbox state
  const visibleIds = body.querySelectorAll('.alert-check');
  const allChecked = visibleIds.length > 0 && Array.from(visibleIds).every(c => c.checked);
  selectAllCb.checked = allChecked;
  selectAllCb.indeterminate = !allChecked && Array.from(visibleIds).some(c => c.checked);
}

body.addEventListener('change', (e) => {
  const cb = e.target.closest('.alert-check');
  if (!cb) return;
  const id = parseInt(cb.dataset.id);
  if (cb.checked) selectedIds.add(id); else selectedIds.delete(id);
  updateBulkBar();
});

selectAllCb.addEventListener('change', () => {
  body.querySelectorAll('.alert-check').forEach(cb => {
    cb.checked = selectAllCb.checked;
    const id = parseInt(cb.dataset.id);
    if (selectAllCb.checked) selectedIds.add(id); else selectedIds.delete(id);
  });
  updateBulkBar();
});

async function bulkApply(patch, label) {
  if (!selectedIds.size) return;
  const ids = Array.from(selectedIds);
  setStatusBanner(`Applying "${label}" to ${ids.length} alerts…`, 'info');
  try {
    const res = await AisecAPI.bulkUpdateAlerts(ids, patch);
    selectedIds.clear();
    setStatusBanner(`${label}: ${res.applied}/${res.requested} alerts updated`, 'success');
    setTimeout(() => setStatusBanner(''), 3500);
    await reload();
  } catch (err) {
    setStatusBanner('Bulk update failed: ' + err.message, 'error');
  }
}

document.getElementById('bulkAck').addEventListener('click',     () => bulkApply({ status:'INVESTIGATING' }, 'Investigating'));
document.getElementById('bulkResolve').addEventListener('click', () => bulkApply({ status:'RESOLVED' },      'Resolved'));
document.getElementById('bulkFp').addEventListener('click',      () => bulkApply({ status:'FALSE_POSITIVE', mlFeedback:'FALSE_POSITIVE' }, 'False Positive'));
document.getElementById('bulkClear').addEventListener('click',   () => { selectedIds.clear(); render(); });

// ===== Toolbar events =====
if (_initialSearch) document.getElementById('alertSearch').value = _initialSearch;
document.getElementById('alertSearch').addEventListener('input', (e) => { state.search = e.target.value; state.page=1; render(); });
document.getElementById('sevFilter').addEventListener('change', (e) => { state.sev = e.target.value; state.page=1; render(); });
document.getElementById('sortBy').addEventListener('change', (e) => { state.sort = e.target.value; render(); });
pager.addEventListener('click', (e) => {
  const btn = e.target.closest('button'); if (!btn) return;
  const go = btn.dataset.go;
  const totalPages = Math.max(1, Math.ceil(alertsData.length / state.perPage));
  if (go === 'prev') state.page = Math.max(1, state.page - 1);
  else if (go === 'next') state.page = Math.min(totalPages, state.page + 1);
  else state.page = parseInt(go);
  render();
});

// ----- Auto resolve modal -----
function closeModalBySelector(sel) {
  const target = document.querySelector(sel);
  if (target) target.classList.remove('show');
}

document.querySelectorAll('[data-close]').forEach(btn => {
  btn.addEventListener('click', () => closeModalBySelector(btn.dataset.close));
});

if (autoResolveBtn && autoModal) {
  autoResolveBtn.addEventListener('click', () => {
    autoModal.classList.add('show');
    autoPreview.textContent = 'Preview will show how many alerts match before closing them.';
  });
  autoModal.addEventListener('click', (e) => {
    if (e.target === autoModal) autoModal.classList.remove('show');
  });
}

function buildAutoPayload() {
  const limit = Math.max(1, Math.min(parseInt(autoLimit.value || '100', 10) || 100, 500));
  const minConfRaw = autoMinConfidence.value.trim();
  const minConfidence = minConfRaw ? Math.min(1, Math.max(0, parseFloat(minConfRaw))) : null;
  return {
    maxSeverity: (autoMaxSeverity.value || 'MEDIUM').toUpperCase(),
    minConfidence,
    limit,
    reason: autoReason.value.trim() || 'noise sweep'
  };
}

async function handleAutoResolve(dryRun = false) {
  if (!window.AisecAPI) return;
  const payload = buildAutoPayload();
  payload.dryRun = dryRun;
  try {
    const res = await AisecAPI.autoResolveAlerts(payload);
    if (dryRun) {
      const matched = res.matched ?? 0;
      if (matched === 0) {
        autoPreview.textContent = 'No alerts match the current criteria.';
      } else {
        autoPreview.textContent = `Preview: ${matched} alert(s) match. Resolving will affect up to ${payload.limit}.`;
      }
    } else {
      const resolved = res.resolved ?? 0;
      closeModalBySelector('#autoResolveModal');
      setStatusBanner(`AI auto-resolve closed ${resolved} alert(s).`, 'success');
      setTimeout(() => setStatusBanner(''), 3500);
      await reload();
    }
  } catch (err) {
    if (dryRun) {
      autoPreview.textContent = 'Preview failed: ' + err.message;
    } else {
      setStatusBanner('Auto-resolve failed: ' + err.message, 'error');
    }
  }
}

document.getElementById('autoPreviewBtn')?.addEventListener('click', () => handleAutoResolve(true));
document.getElementById('autoConfirmBtn')?.addEventListener('click', () => handleAutoResolve(false));

// ===== Modal =====
const modal = document.getElementById('alertModal');
let modalAlertId = null;

document.getElementById('closeModal').addEventListener('click', () => modal.classList.remove('show'));
modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.remove('show'); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') modal.classList.remove('show'); });

async function openModal(id){
  const a = alertsData.find(x => x.id === id); if (!a) return;
  modalAlertId = id;
  modal.classList.add('show');

  document.getElementById('mId').textContent = 'INC-' + String(a.id).padStart(3,'0');
  document.getElementById('mTitle').textContent = a.attack_type || 'Unknown';
  const sev = document.getElementById('mSev');
  sev.textContent = a.severity || '—';
  sev.className = 'badge-sev ' + (a.severity || '').toLowerCase();
  const flag = flagEmoji(a.src_country);
  document.getElementById('mIp').textContent = (flag ? flag + ' ' : '') + (a.source_ip || '—');
  document.getElementById('mStatus').textContent = a.status || '—';
  document.getElementById('mTime').textContent = timeAgo(a.created_at);
  document.getElementById('mMitre').textContent = a.mitre_technique || '—';
  document.getElementById('mDesc').textContent = a.description || '—';
  renderExplanation(a.explanation);
  const icoWrap = document.querySelector('.modal-ico');
  icoWrap.innerHTML = `<i class="fa-solid ${iconFor(a.attack_type)}"></i>`;

  // ----- Assignee dropdown -----
  const assignee = document.getElementById('mAssignee');
  assignee.innerHTML = '<option value="-1">— Unassigned —</option>' +
      usersData.map(u => `<option value="${u.id}" ${a.assigned_to_id === u.id ? 'selected':''}>${u.username}</option>`).join('');
  assignee.onchange = async () => {
    try {
      const updated = await AisecAPI.patchAlert(a.id, { assignedToId: parseInt(assignee.value) });
      replaceAlert(updated);
      setStatusBanner('Assignment updated', 'success');
      setTimeout(() => setStatusBanner(''), 2500);
    } catch (err) {
      setStatusBanner('Assignment failed: ' + err.message, 'error');
    }
  };

  // ----- ML feedback buttons -----
  const fbBadge = document.getElementById('mFbBadge');
  fbBadge.textContent = a.ml_feedback ? `Current: ${a.ml_feedback.replace('_',' ')}` : '';
  modal.querySelectorAll('[data-fb]').forEach(btn => {
    btn.onclick = async () => {
      try {
        const updated = await AisecAPI.patchAlert(a.id, { mlFeedback: btn.dataset.fb });
        replaceAlert(updated);
        fbBadge.textContent = `Saved: ${updated.ml_feedback.replace('_',' ')}`;
      } catch (err) {
        setStatusBanner('Feedback failed: ' + err.message, 'error');
      }
    };
  });

  // ----- Status action buttons -----
  document.getElementById('mBtnInvestigate').onclick = () => changeStatus(a.id, 'INVESTIGATING');
  document.getElementById('mBtnFp').onclick          = () => changeStatus(a.id, 'FALSE_POSITIVE');
  document.getElementById('mBtnResolve').onclick     = () => changeStatus(a.id, 'RESOLVED');

  // ----- Comments thread -----
  loadComments(a.id);

  // Re-apply role gating to freshly-rendered modal controls
  if (window.AisecAPI && AisecAPI.applyRbac) AisecAPI.applyRbac(modal);
}

function replaceAlert(updated) {
  const idx = alertsData.findIndex(x => x.id === updated.id);
  if (idx >= 0) alertsData[idx] = updated;
  render();
}

async function changeStatus(id, status) {
  try {
    const updated = await AisecAPI.updateAlert(id, status);
    replaceAlert(updated);
    modal.classList.remove('show');
    setStatusBanner(`Alert #${id} marked as ${status.replace('_',' ')}`, 'success');
    setTimeout(() => setStatusBanner(''), 3000);
  } catch (err) {
    setStatusBanner('Failed to update: ' + err.message, 'error');
  }
}

async function loadComments(id) {
  const wrap = document.getElementById('mComments');
  const count = document.getElementById('mCommentCount');
  wrap.innerHTML = '<div class="muted sm" style="padding:6px">Loading…</div>';
  try {
    const list = await AisecAPI.listAlertComments(id);
    count.textContent = list.length ? `(${list.length})` : '';
    if (!list.length) {
      wrap.innerHTML = '<div class="muted sm" style="padding:6px">No notes yet. Be the first.</div>';
      return;
    }
    wrap.innerHTML = list.map(c => `
      <div style="padding:9px 12px;background:#0b1628;border:1px solid #1e3557;border-radius:8px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
          <strong style="font-size:13px;color:#a5f3fc">${escapeHtml(c.author_username || 'system')}</strong>
          <span class="muted sm">${timeAgo(c.created_at)}</span>
        </div>
        <div style="font-size:13px;color:#e2e8f0;line-height:1.5;white-space:pre-wrap">${escapeHtml(c.body)}</div>
      </div>
    `).join('');
    wrap.scrollTop = wrap.scrollHeight;
  } catch (err) {
    wrap.innerHTML = `<div class="muted sm" style="padding:6px;color:#fecaca">Failed to load notes.</div>`;
  }
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, m => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[m]));
}

const commentInput = document.getElementById('mCommentInput');
const commentSend  = document.getElementById('mCommentSend');
async function postComment() {
  const text = commentInput.value.trim();
  if (!text || !modalAlertId) return;
  commentSend.disabled = true;
  try {
    await AisecAPI.addAlertComment(modalAlertId, text);
    commentInput.value = '';
    await loadComments(modalAlertId);
  } catch (err) {
    setStatusBanner('Failed to post note: ' + err.message, 'error');
  } finally {
    commentSend.disabled = false;
  }
}
commentSend.addEventListener('click', postComment);
commentInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') postComment(); });

// ===== Initial load + WebSocket live updates =====
async function fetchAllAlerts() {
  const size = 1000;
  const first = await AisecAPI.listAlerts({ page: 0, size });
  const content = first.content || [];
  const totalPages = first.total_pages ?? first.totalPages ?? 1;
  if (totalPages <= 1) return content;

  const rest = [];
  for (let page = 1; page < totalPages; page++) {
    rest.push(AisecAPI.listAlerts({ page, size }));
  }
  const pages = await Promise.all(rest);
  return content.concat(...pages.map(p => p.content || []));
}

async function reload() {
  try {
    alertsData = await fetchAllAlerts();
    render();
  } catch (err) {
    console.warn('reload failed:', err.message);
  }
}

async function load() {
  if (!window.AisecAPI) {
    setStatusBanner('API client not loaded', 'error');
    return;
  }
  try {
    setStatusBanner('Loading alerts from backend…', 'info');
    const [allAlerts, users] = await Promise.all([
      fetchAllAlerts(),
      AisecAPI.listUsers().catch(() => [])  // VIEWER role can't list users; that's fine
    ]);
    alertsData = allAlerts;
    usersData  = Array.isArray(users) ? users : (users.content || []);
    setStatusBanner(`Loaded ${alertsData.length} alerts · Live updates ENABLED`, 'success');
    setTimeout(() => setStatusBanner(''), 3000);
    render();
  } catch (err) {
    console.error(err);
    setStatusBanner('Failed to load alerts: ' + err.message, 'error');
  }

  // Debounced full reload — replaces individual prepends to avoid 200x renders
  let reloadTimer = null;
  function scheduleFullReload(reason) {
    clearTimeout(reloadTimer);
    reloadTimer = setTimeout(async () => {
      await reload();
      if (reason) {
        setStatusBanner(reason, 'info');
        setTimeout(() => setStatusBanner(''), 3500);
      }
    }, 400);
  }

  // WebSocket live feed
  try {
    AisecAPI.connectAlertsWS({
      onMessage: (msg) => {
        if (!msg) return;
        if (msg.type === 'alert' && msg.data) {
          alertsData.unshift(msg.data);
          render();
          scheduleFullReload();
        } else if (msg.type === 'scan_complete') {
          const d = msg.data || {};
          scheduleFullReload(`Scan complete: ${d.attack_count || 0} new attacks · ${d.total_flows || 0} flows`);
        }
      },
      onClose: () => console.warn('Alerts WS disconnected')
    });
  } catch (e) {
    console.warn('WS init failed:', e);
  }
}

load();

// ===== Export CSV =====
document.getElementById('exportBtn').addEventListener('click', () => {
  const headers = ['ID','Type','Severity','Source IP','SrcCC','Dest IP','Status','Assigned','ML Feedback','Time','MITRE','Description'];
  const rows = alertsData.filter(a => {
    const q = state.search.toLowerCase();
    const matchQ = !q ||
      String(a.id).includes(q) ||
      (a.attack_type || '').toLowerCase().includes(q) ||
      (a.source_ip || '').includes(q);
    const matchS = !state.sev || (a.severity || '').toLowerCase() === state.sev.toLowerCase();
    return matchQ && matchS;
  });
  if (!rows.length) return;
  const esc = v => `"${String(v ?? '').replace(/"/g,'""')}"`;
  const csv = [
    headers.join(','),
    ...rows.map(a => [
      'INC-' + String(a.id).padStart(3,'0'),
      a.attack_type || '',
      a.severity || '',
      a.source_ip || '',
      a.src_country || '',
      a.dest_ip || '',
      a.status || '',
      a.assigned_to_username || '',
      a.ml_feedback || '',
      a.created_at || '',
      a.mitre_technique || '',
      a.description || ''
    ].map(esc).join(','))
  ].join('\r\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url  = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href     = url;
  link.download = `alerts-${new Date().toISOString().slice(0,10)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
});

// ===== Columns toggle =====
const colsBtn   = document.getElementById('colsBtn');
const colsPanel = document.getElementById('colsPanel');
const hiddenCols = new Set();

colsBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  colsPanel.style.display = colsPanel.style.display === 'none' ? 'block' : 'none';
});
document.addEventListener('click', (e) => {
  if (!colsPanel.contains(e.target) && e.target !== colsBtn) {
    colsPanel.style.display = 'none';
  }
});

document.querySelectorAll('.col-toggle').forEach(lbl => {
  lbl.addEventListener('click', () => {
    const col = parseInt(lbl.dataset.col);
    if (hiddenCols.has(col)) {
      hiddenCols.delete(col);
      lbl.classList.remove('hidden');
    } else {
      hiddenCols.add(col);
      lbl.classList.add('hidden');
    }
    applyColVisibility();
  });
});

function applyColVisibility() {
  const table = document.querySelector('.alerts-table');
  if (!table) return;
  // col indices shifted by 1 after adding the select column at position 0
  // 0=Select, 1=ID, 2=Type, 3=Severity, 4=SourceIP, 5=Status, 6=Assigned, 7=Time, 8=Actions
  table.querySelectorAll('tr').forEach(tr => {
    tr.querySelectorAll('th, td').forEach((cell, i) => {
      // The data-col values from the panel still refer to the OLD positions [1..5]
      // which now correspond to indices [2..6] in the new layout.
      const visIdx = [2,3,4,5,7].includes(i) ? (i === 7 ? 5 : i - 1) : null;
      if (visIdx !== null) {
        cell.style.display = hiddenCols.has(visIdx) ? 'none' : '';
      }
    });
  });
}
