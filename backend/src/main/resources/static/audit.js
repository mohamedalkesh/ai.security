// Audit Log viewer — admin-only.
if (window.AisecAPI) AisecAPI.requireAuth();

// Reveal animations
const _io = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting){ e.target.classList.add('visible'); _io.unobserve(e.target); }});
}, { threshold:.1 });
document.querySelectorAll('.reveal').forEach(el => _io.observe(el));

// Hard gate: VIEWERs/ANALYSTs shouldn't be on this page.
(function gate() {
  if (!window.AisecAPI) return;
  if (!AisecAPI.hasRole('ADMIN', 'ORG_ADMIN')) {
    location.href = 'dashboard.html';
  }
})();

const body      = document.getElementById('auditBody');
const pageInfo  = document.getElementById('auditPageInfo');
const pager     = document.getElementById('auditPager');
const search    = document.getElementById('auditSearch');
const actionSel = document.getElementById('actionFilter');

let rows = [];
let state = { page: 0, size: 50, totalPages: 1, search: '', action: '' };

function timeAgo(iso) {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  const diff = (Date.now() - t) / 1000;
  if (diff < 60)    return Math.floor(diff) + 's ago';
  if (diff < 3600)  return Math.floor(diff/60) + 'm ago';
  if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
  return Math.floor(diff/86400) + 'd ago';
}

function fullTime(iso) {
  if (!iso) return '';
  return new Date(iso).toLocaleString();
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, m => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[m]));
}

function renderRows(list) {
  if (!list.length) {
    body.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--muted)">No audit entries match.</td></tr>`;
    return;
  }
  body.innerHTML = list.map((r, i) => {
    const cls = `act-${r.action}`;
    const known = ['LOGIN_OK','LOGIN_FAIL','REGISTER_OK','RATE_LIMIT','ALERT_STATUS','ALERT_UPDATE','ALERT_DELETE','ALERT_BULK','ALERT_COMMENT'];
    const pillClass = known.includes(r.action) ? cls : 'act-default';
    const resource = r.resource_type
        ? `${escapeHtml(r.resource_type)}${r.resource_id ? ' #' + escapeHtml(r.resource_id) : ''}`
        : '<span class="muted sm">—</span>';
    return `
    <tr class="audit-row" style="animation-delay:${i*30}ms">
      <td title="${escapeHtml(fullTime(r.created_at))}">
        <div style="font-size:13px;color:#e2e8f0">${timeAgo(r.created_at)}</div>
        <div class="muted sm">${new Date(r.created_at).toLocaleTimeString()}</div>
      </td>
      <td><span class="action-pill ${pillClass}">${escapeHtml(r.action)}</span></td>
      <td>
        <div style="font-weight:600;color:#e2e8f0">${escapeHtml(r.actor_username || '—')}</div>
        ${r.actor_role ? `<div class="muted sm">${escapeHtml(r.actor_role)}</div>` : ''}
      </td>
      <td>${resource}</td>
      <td class="audit-mono">${escapeHtml(r.source_ip || '—')}</td>
      <td class="audit-mono" style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="${escapeHtml(r.details || '')}">${escapeHtml(r.details || '—')}</td>
    </tr>`;
  }).join('');
}

function renderPager() {
  let html = `<button class="nav-btn" ${state.page===0?'disabled':''} data-go="prev">Previous</button>`;
  const startPage = Math.max(0, Math.min(state.page - 2, state.totalPages - 5));
  for (let i = startPage; i < Math.min(startPage + 5, state.totalPages); i++) {
    html += `<button class="${i===state.page?'active':''}" data-go="${i}">${i+1}</button>`;
  }
  html += `<button class="nav-btn" ${state.page>=state.totalPages-1?'disabled':''} data-go="next">Next</button>`;
  pager.innerHTML = html;
}

function applyClientFilter() {
  const q = state.search.toLowerCase();
  if (!q) { renderRows(rows); return; }
  renderRows(rows.filter(r =>
    (r.actor_username || '').toLowerCase().includes(q) ||
    (r.resource_type || '').toLowerCase().includes(q) ||
    (r.resource_id || '').toLowerCase().includes(q) ||
    (r.source_ip || '').includes(q) ||
    (r.details || '').toLowerCase().includes(q)
  ));
}

function updateCounters() {
  const cnt = (a) => rows.filter(r => r.action === a).length;
  document.getElementById('cntLoginOk').textContent   = cnt('LOGIN_OK');
  document.getElementById('cntLoginFail').textContent = cnt('LOGIN_FAIL');
  document.getElementById('cntRateLimit').textContent = cnt('RATE_LIMIT');
}

async function load() {
  if (!window.AisecAPI) return;
  pageInfo.textContent = 'Loading…';
  try {
    const params = { page: state.page, size: state.size };
    if (state.action) params.action = state.action;
    const page = await AisecAPI.listAuditLogs(params);
    rows = page.content || [];
    state.totalPages = Math.max(1, page.total_pages || 1);
    pageInfo.textContent = `Page ${state.page + 1} of ${state.totalPages} · ${page.total_elements ?? rows.length} total events`;
    updateCounters();
    applyClientFilter();
    renderPager();
  } catch (err) {
    body.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:30px;color:#fca5a5">
        Failed to load audit log: ${escapeHtml(err.message)}</td></tr>`;
    pageInfo.textContent = '';
  }
}

// Events
search.addEventListener('input', (e) => {
  state.search = e.target.value;
  applyClientFilter();
});
actionSel.addEventListener('change', (e) => {
  state.action = e.target.value;
  state.page = 0;
  load();
});
pager.addEventListener('click', (e) => {
  const btn = e.target.closest('button'); if (!btn || btn.disabled) return;
  const go = btn.dataset.go;
  if (go === 'prev') state.page = Math.max(0, state.page - 1);
  else if (go === 'next') state.page = Math.min(state.totalPages - 1, state.page + 1);
  else state.page = parseInt(go);
  load();
});
document.getElementById('refreshAuditBtn').addEventListener('click', load);

document.getElementById('exportAuditBtn').addEventListener('click', () => {
  if (!rows.length) return;
  const headers = ['When','Action','Actor','Role','Resource','ResourceId','SourceIP','Details'];
  const esc = v => `"${String(v ?? '').replace(/"/g,'""')}"`;
  const csv = [headers.join(','),
    ...rows.map(r => [
      r.created_at || '',
      r.action || '',
      r.actor_username || '',
      r.actor_role || '',
      r.resource_type || '',
      r.resource_id || '',
      r.source_ip || '',
      r.details || ''
    ].map(esc).join(','))
  ].join('\r\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `audit-log-${new Date().toISOString().slice(0,10)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
});

load();
