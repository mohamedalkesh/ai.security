if (window.AisecAPI) AisecAPI.requireAuth();

const _io = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting){ e.target.classList.add('visible'); _io.unobserve(e.target); }});
}, { threshold:.1 });
document.querySelectorAll('.reveal').forEach(el => _io.observe(el));

const list      = document.getElementById('incList');
const loading   = document.getElementById('incLoading');
const search    = document.getElementById('incSearch');
const statusSel = document.getElementById('incStatusFilter');

let incidents = [];
let state = { search: '', status: '' };

const SEV_COLORS = {
  CRITICAL: { bg: 'rgba(239,68,68,.18)', fg: '#fca5a5' },
  HIGH:     { bg: 'rgba(245,158,11,.18)', fg: '#fcd34d' },
  MEDIUM:   { bg: 'rgba(34,184,207,.18)', fg: '#a5f3fc' },
  LOW:      { bg: 'rgba(168,85,247,.18)', fg: '#d8b4fe' },
  INFORMATIONAL: { bg: 'rgba(150,160,180,.18)', fg: '#cbd5e1' }
};
const STATUS_COLORS = {
  NEW:            { bg: 'rgba(239,68,68,.18)', fg: '#fca5a5' },
  INVESTIGATING:  { bg: 'rgba(245,158,11,.18)', fg: '#fcd34d' },
  RESOLVED:       { bg: 'rgba(34,197,94,.15)', fg: '#86efac' },
  FALSE_POSITIVE: { bg: 'rgba(150,160,180,.15)', fg: '#cbd5e1' }
};

function timeAgo(iso) {
  if (!iso) return '';
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60)    return Math.floor(diff) + 's';
  if (diff < 3600)  return Math.floor(diff/60) + 'm';
  if (diff < 86400) return Math.floor(diff/3600) + 'h';
  return Math.floor(diff/86400) + 'd';
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, m => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[m]));
}

function pill(text, kind, map, extra = '') {
  const c = map[kind] || { bg: 'rgba(150,160,180,.15)', fg: '#cbd5e1' };
  return `<span class="inc-pill" style="background:${c.bg};color:${c.fg}">${escapeHtml(text)}${extra}</span>`;
}

function render() {
  loading.style.display = 'none';
  const q = state.search.toLowerCase();
  const filtered = incidents.filter(i => {
    const matchQ = !q ||
      (i.title || '').toLowerCase().includes(q) ||
      (i.source_ip || '').includes(q);
    const matchS = !state.status || i.status === state.status;
    return matchQ && matchS;
  });

  // Counters
  const open = incidents.filter(i => i.status === 'NEW' || i.status === 'INVESTIGATING').length;
  const resolved = incidents.filter(i => i.status === 'RESOLVED').length;
  document.getElementById('incOpen').textContent     = open;
  document.getElementById('incResolved').textContent = resolved;

  if (!filtered.length) {
    list.innerHTML = `<div class="muted sm" style="padding:30px;text-align:center">
      No incidents match your filters. Incidents are created automatically when correlated alerts arrive.</div>`;
    return;
  }

  list.innerHTML = filtered.map(i => `
    <div class="inc-card" data-id="${i.id}">
      <div>
        <div class="inc-title">
          <i class="fa-solid fa-layer-group" style="color:#22b8cf;margin-right:6px"></i>
          ${escapeHtml(i.title || 'Incident')}
        </div>
        <div class="inc-sub">
          Source: <span style="color:#a5f3fc">${escapeHtml(i.source_ip || '—')}</span>
          · First seen ${timeAgo(i.created_at)} ago
          · Last alert ${timeAgo(i.last_alert_at)} ago
          ${i.assigned_to_username ? '· <i class="fa-solid fa-user"></i> ' + escapeHtml(i.assigned_to_username) : ''}
        </div>
      </div>
      <div class="inc-meta">
        ${pill(i.highest_severity || '—', i.highest_severity, SEV_COLORS)}
        ${pill(i.status || '—', i.status, STATUS_COLORS)}
        <span class="inc-pill" style="background:rgba(34,184,207,.15);color:#a5f3fc">
          <i class="fa-solid fa-triangle-exclamation"></i>
          <span class="num">${i.alert_count || 0}</span> alerts
        </span>
      </div>
    </div>
  `).join('');

  // Click → filter alerts page by source IP (a poor man's drill-down).
  list.querySelectorAll('.inc-card').forEach(card => {
    card.addEventListener('click', () => {
      // No dedicated detail page yet — bounce to alerts filtered by srcIp.
      // (Future: a dedicated incidents/detail page showing the timeline.)
      const inc = incidents.find(x => x.id === parseInt(card.dataset.id));
      if (inc && inc.source_ip) {
        sessionStorage.setItem('alerts_search', inc.source_ip);
        location.href = 'alerts.html';
      }
    });
  });
}

async function load() {
  if (!window.AisecAPI) return;
  loading.style.display = 'block';
  loading.textContent = 'Loading incidents…';
  try {
    const page = await AisecAPI.listIncidents({ size: 200 });
    incidents = page.content || [];
    render();
  } catch (err) {
    loading.style.display = 'block';
    loading.textContent = 'Failed to load incidents: ' + err.message;
    loading.style.color = '#fca5a5';
  }
}

search.addEventListener('input',     e => { state.search = e.target.value; render(); });
statusSel.addEventListener('change', e => { state.status = e.target.value; render(); });
document.getElementById('incRefresh').addEventListener('click', load);

load();
