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
  body.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:30px;color:var(--muted)">Loading…</td></tr>`;

  try {
    const data = await API.trainingList(params);
    totalPages = data.totalPages ?? 1;
    document.getElementById('recCount').textContent =
      data.totalElements + ' record' + (data.totalElements !== 1 ? 's' : '');
    renderTable(data.content ?? []);
    renderPagination(data.totalPages ?? 1, page, data.totalElements ?? 0);
  } catch (e) {
    body.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:30px;color:#ff6b6b">Failed to load: ${e.message}</td></tr>`;
  }
}

function renderTable(rows) {
  const body = document.getElementById('tableBody');
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:40px;color:var(--muted)">No training records yet</td></tr>`;
    return;
  }
  body.innerHTML = rows.map((r, i) => `
    <tr style="cursor:pointer;animation-delay:${i*.03}s" onclick="showDetail(${JSON.stringify(r).replace(/"/g,'&quot;')})">
      <td class="mono">${r.id}</td>
      <td><span class="label-chip ${r.trueLabel === 'ATTACK' ? 'attack' : 'benign'}">${r.trueLabel}</span></td>
      <td style="font-weight:600;color:var(--text)">${esc(r.attackType)}</td>
      <td><span class="sev-chip ${r.severity}">${r.severity}</span></td>
      <td class="mono">${r.confidence != null ? (r.confidence * 100).toFixed(1) + '%' : '—'}</td>
      <td class="mono">${esc(r.sourceIp) || '—'}</td>
      <td>${esc(r.protocol) || '—'}</td>
      <td class="dim">${esc(r.mitreTactic) || '—'}</td>
      <td class="dim">${fmtDate(r.resolvedAt)}</td>
    </tr>`).join('');
}

// ── Detail Panel ──────────────────────────────────────────────────────────────
function showDetail(r) {
  const panel = document.getElementById('detailPanel');
  panel.style.display = 'block';
  document.getElementById('detailId').textContent = '#' + r.id;

  const fields = [
    ['Alert ID',         r.alertId],
    ['True Label',       r.trueLabel],
    ['Attack Type',      r.attackType],
    ['Severity',         r.severity],
    ['Confidence',       r.confidence != null ? (r.confidence * 100).toFixed(2) + '%' : '—'],
    ['Source IP',        r.sourceIp],
    ['Dest IP',          r.destIp],
    ['Dest Port',        r.destPort],
    ['Protocol',         r.protocol],
    ['MITRE Technique',  r.mitreTechnique],
    ['MITRE Tactic',     r.mitreTactic],
    ['Resolution',       r.resolutionStatus],
    ['Alert Created',    fmtDate(r.alertCreatedAt)],
    ['Resolved At',      fmtDate(r.resolvedAt)],
  ];

  document.getElementById('detailGrid').innerHTML = fields.map(([lbl, val]) => `
    <div class="detail-item">
      <label>${lbl}</label>
      <span>${esc(val) || '<span class="dim">—</span>'}</span>
    </div>`).join('');

  const featWrap = document.getElementById('featuresWrap');
  const featBox  = document.getElementById('featuresBox');
  if (r.featuresJson) {
    try {
      const parsed = JSON.parse(r.featuresJson);
      featBox.textContent = JSON.stringify(parsed, null, 2);
    } catch (_) {
      featBox.textContent = r.featuresJson;
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
  return String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function showToast(msg, type) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.querySelector('span').textContent = msg;
  t.style.background = type === 'error' ? '#c0392b' : '';
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3000);
}
