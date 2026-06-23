'use strict';

const API = window.AisecAPI;
let currentPage = 0;

const _io = new IntersectionObserver((entries) => {
  entries.forEach(e => {
    if (e.isIntersecting) { e.target.classList.add('visible'); _io.unobserve(e.target); }
  });
}, { threshold: .12 });
document.querySelectorAll('.reveal').forEach(el => _io.observe(el));
let totalPages  = 0;
let debTimer    = null;

// ── Init ──────────────────────────────────────────────────────────────────────
(async () => {
  if (!API.isAuthenticated()) { API.logout(); return; }
  API.applyRbac();
  setupExportBtn();
  await Promise.all([loadStats(), loadPage(0)]);
})();

// ── Stats KPIs ────────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const s = await API.trainingStats();
    document.getElementById('kTotal').textContent  = (s.total  ?? 0).toLocaleString();
    document.getElementById('kAttack').textContent = (s.attack ?? 0).toLocaleString();
    document.getElementById('kBenign').textContent = (s.benign ?? 0).toLocaleString();
  } catch (_) {}
}

// ── Table ─────────────────────────────────────────────────────────────────────
async function loadPage(page) {
  currentPage = page;
  const attackType = document.getElementById('fAttack').value.trim();
  const label      = document.getElementById('fLabel').value;

  const params = { page, size: 50 };
  if (label)      params.label      = label;
  if (attackType) params.attackType = attackType;

  const body = document.getElementById('tableBody');
  body.innerHTML = `<tr><td colspan="11" style="text-align:center;padding:30px;color:var(--muted)">Loading…</td></tr>`;

  try {
    const data = await API.trainingList(params);
    totalPages = data.totalPages ?? 1;
    document.getElementById('recCount').textContent =
      data.totalElements + ' record' + (data.totalElements !== 1 ? 's' : '');
    renderTable(data.content ?? []);
    renderPagination(data.totalPages ?? 1, page, data.totalElements ?? 0);
  } catch (e) {
    body.innerHTML = `<tr><td colspan="11" style="text-align:center;padding:30px;color:#ff6b6b">Failed to load: ${e.message}</td></tr>`;
  }
}

function renderTable(rows) {
  const body = document.getElementById('tableBody');
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="11" style="text-align:center;padding:40px;color:var(--muted)">No training records yet</td></tr>`;
    return;
  }
  body.innerHTML = rows.map((r, i) => {
    const trueLabel = field(r, 'trueLabel', 'true_label');
    const severity = field(r, 'severity');
    const confidence = field(r, 'confidence');
    const responseAction = field(r, 'responseAction', 'response_action');
    return `
    <tr style="cursor:pointer;animation-delay:${i*.03}s" onclick="showDetail(${JSON.stringify(r).replace(/"/g,'&quot;')})">
      <td class="mono">${field(r, 'id')}</td>
      <td><span class="label-chip ${trueLabel === 'ATTACK' ? 'attack' : 'benign'}">${esc(trueLabel) || '—'}</span></td>
      <td style="font-weight:600;color:var(--text)">${esc(field(r, 'attackType', 'attack_type')) || '—'}</td>
      <td><span class="sev-chip ${esc(severity)}">${esc(severity) || '—'}</span></td>
      <td class="mono">${confidence != null ? (Number(confidence) * 100).toFixed(1) + '%' : '—'}</td>
      <td class="mono">${esc(field(r, 'sourceIp', 'source_ip')) || '—'}</td>
      <td>${esc(field(r, 'protocol')) || '—'}</td>
      <td class="dim">${esc(field(r, 'mitreTactic', 'mitre_tactic')) || '—'}</td>
      <td>${decisionChip(field(r, 'responseDecision', 'response_decision'))}</td>
      <td class="dim" title="${esc(responseAction)}">${shortText(responseAction, 42)}</td>
      <td class="dim">${fmtDate(field(r, 'resolvedAt', 'resolved_at'))}</td>
    </tr>`;
  }).join('');
}

// ── Detail Panel ──────────────────────────────────────────────────────────────
function showDetail(r) {
  const panel = document.getElementById('detailPanel');
  panel.style.display = 'block';
  document.getElementById('detailId').textContent = '#' + field(r, 'id');
  const confidence = field(r, 'confidence');

  const fields = [
    ['Alert ID',         field(r, 'alertId', 'alert_id')],
    ['True Label',       field(r, 'trueLabel', 'true_label')],
    ['Attack Type',      field(r, 'attackType', 'attack_type')],
    ['Severity',         field(r, 'severity')],
    ['Confidence',       confidence != null ? (Number(confidence) * 100).toFixed(2) + '%' : '—'],
    ['Source IP',        field(r, 'sourceIp', 'source_ip')],
    ['Dest IP',          field(r, 'destIp', 'dest_ip')],
    ['Dest Port',        field(r, 'destPort', 'dest_port')],
    ['Protocol',         field(r, 'protocol')],
    ['Source Country',   field(r, 'srcCountry', 'src_country')],
    ['Destination Country', field(r, 'dstCountry', 'dst_country')],
    ['MITRE Technique',  field(r, 'mitreTechnique', 'mitre_technique')],
    ['MITRE Tactic',     field(r, 'mitreTactic', 'mitre_tactic')],
    ['ML Feedback',      field(r, 'mlFeedback', 'ml_feedback')],
    ['Assigned To',      field(r, 'assignedToUsername', 'assigned_to_username')],
    ['Incident ID',      field(r, 'incidentId', 'incident_id')],
    ['Decision',         field(r, 'responseDecision', 'response_decision')],
    ['Resolution',       field(r, 'resolutionStatus', 'resolution_status')],
    ['Alert Created',    fmtDate(field(r, 'alertCreatedAt', 'alert_created_at'))],
    ['Resolved At',      fmtDate(field(r, 'resolvedAt', 'resolved_at'))],
  ];

  document.getElementById('detailGrid').innerHTML = fields.map(([lbl, val]) => `
    <div class="detail-item">
      <label>${lbl}</label>
      <span>${esc(val) || '<span class="dim">—</span>'}</span>
    </div>`).join('') + `
    <div class="detail-section">
      <label>Response Action</label>
      <div>${esc(field(r, 'responseAction', 'response_action')) || '<span class="dim">—</span>'}</div>
    </div>
    <div class="detail-section">
      <label>Attack Description</label>
      <div>${esc(field(r, 'description')) || '<span class="dim">—</span>'}</div>
    </div>`;

  const featWrap = document.getElementById('featuresWrap');
  const featBox  = document.getElementById('featuresBox');
  const featuresJson = field(r, 'featuresJson', 'features_json');
  if (featuresJson) {
    try {
      const parsed = JSON.parse(featuresJson);
      featBox.textContent = JSON.stringify(parsed, null, 2);
    } catch (_) {
      featBox.textContent = featuresJson;
    }
    featWrap.style.display = '';
  } else {
    featWrap.style.display = 'none';
  }

  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ── Pagination ────────────────────────────────────────────────────────────────
function renderPagination(total, current, totalElements) {
  const pag = document.getElementById('pagination');
  if (total <= 1) { pag.innerHTML = ''; return; }
  const pages = [];
  pages.push(`<button ${current === 0 ? 'disabled' : ''} onclick="loadPage(${current - 1})">‹ Prev</button>`);
  const from = Math.max(0, current - 2);
  const to   = Math.min(total - 1, current + 2);
  for (let p = from; p <= to; p++) {
    pages.push(`<button class="${p === current ? 'active' : ''}" onclick="loadPage(${p})">${p + 1}</button>`);
  }
  pages.push(`<button ${current >= total - 1 ? 'disabled' : ''} onclick="loadPage(${current + 1})">Next ›</button>`);
  pages.push(`<span class="page-info">${totalElements} records</span>`);
  pag.innerHTML = pages.join('');
}

// ── Export ────────────────────────────────────────────────────────────────────
function setupExportBtn() {
  const btn = document.getElementById('exportBtn');
  btn.addEventListener('click', async (e) => {
    e.preventDefault();
    try {
      const sess = JSON.parse(localStorage.getItem('aisec_session') || 'null');
      const base = API.base || 'http://127.0.0.1:8080/api';
      const url  = base + '/training-data/export.csv';
      const res  = await fetch(url, {
        headers: { Authorization: 'Bearer ' + (sess?.token || '') }
      });
      if (!res.ok) throw new Error('Export failed');
      const blob = await res.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'training_data_' + new Date().toISOString().slice(0,10) + '.csv';
      a.click();
      showToast('CSV exported');
    } catch (err) {
      showToast('Export failed: ' + err.message, 'error');
    }
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function debounceLoad() {
  clearTimeout(debTimer);
  debTimer = setTimeout(() => loadPage(0), 400);
}

function field(obj, ...names) {
  for (const name of names) {
    if (obj && obj[name] !== undefined && obj[name] !== null) return obj[name];
  }
  return null;
}

function fmtDate(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleString('en-GB', { day:'2-digit', month:'short', year:'numeric',
      hour:'2-digit', minute:'2-digit', hour12:false });
  } catch (_) { return iso; }
}

function esc(v) {
  if (v == null) return '';
  return String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function decisionChip(v) {
  if (!v) return '<span class="dim">—</span>';
  const safe = esc(v);
  return `<span class="decision-chip ${safe}">${safe}</span>`;
}

function shortText(v, max) {
  if (!v) return '—';
  const s = String(v);
  return esc(s.length > max ? s.slice(0, max - 1) + '…' : s);
}

function showToast(msg, type) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.querySelector('span').textContent = msg;
  t.style.background = type === 'error' ? '#c0392b' : '';
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3000);
}
