// Backend auth guard
if (window.AisecAPI) AisecAPI.requireAuth();

// Reveal
const io = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting){ e.target.classList.add('visible'); io.unobserve(e.target); }});
}, { threshold:.08 });
document.querySelectorAll('.reveal').forEach(el => io.observe(el));

// Notifications data — empty by default; populated from real alerts.
let NOTIFS = [];

// Map a backend alert into a notification card
function alertToNotif(a) {
  const sev = (a.severity || '').toUpperCase();
  const type = sev === 'CRITICAL' ? 'critical'
            : sev === 'HIGH' ? 'warning'
            : sev === 'MEDIUM' ? 'info' : 'info';
  const icon = sev === 'CRITICAL' ? 'fa-triangle-exclamation'
             : sev === 'HIGH'     ? 'fa-circle-exclamation'
             : 'fa-bell';
  const t = new Date(a.created_at).getTime();
  const d = (Date.now() - t) / 1000;
  const time = d < 60 ? Math.floor(d) + ' seconds ago'
             : d < 3600 ? Math.floor(d/60) + ' minutes ago'
             : d < 86400 ? Math.floor(d/3600) + ' hours ago'
             : Math.floor(d/86400) + ' days ago';
  return {
    id: a.id, type, icon,
    title: a.attack_type || 'Security Event',
    desc: (a.description || `${sev} severity alert from ${a.source_ip || 'unknown'}`),
    time,
    unread: (a.status || 'NEW') === 'NEW'
  };
}

let filter = 'all';
let visible = 8;

function matchesFilter(n){
  if (filter === 'all') return true;
  if (filter === 'unread') return n.unread;
  if (filter === 'critical') return n.type === 'critical';
  if (filter === 'warning') return n.type === 'warning';
  return true;
}

function render(){
  const list = document.getElementById('notifList');
  const filtered = NOTIFS.filter(matchesFilter).slice(0, visible);
  if (!filtered.length){
    list.innerHTML = `<div class="panel n-empty"><i class="fa-regular fa-bell-slash"></i>No notifications in this category</div>`;
  } else {
    list.innerHTML = filtered.map((n, i) => `
      <div class="notif ${n.type} ${n.unread?'unread':''}" data-id="${n.id}" style="animation-delay:${i*.04}s">
        <div class="notif-ico"><i class="fa-solid ${n.icon}"></i></div>
        <div class="notif-body">
          <div class="notif-title">${n.title}${n.unread?'<span class="unread-dot"></span>':''}</div>
          <div class="notif-desc">${n.desc}</div>
        </div>
        <div class="notif-time">${n.time}</div>
        <div class="notif-actions">
          <button class="n-act read ${n.unread?'':'hidden'}" title="Mark as read" data-read="${n.id}"><i class="fa-solid fa-check"></i></button>
          <button class="n-act del" title="Delete" data-del="${n.id}"><i class="fa-solid fa-trash"></i></button>
        </div>
      </div>
    `).join('');
  }
  updateStats();
  attachActions();
}

function updateStats(){
  const unread = NOTIFS.filter(n => n.unread).length;
  const crit = NOTIFS.filter(n => n.type === 'critical').length;
  const warn = NOTIFS.filter(n => n.type === 'warning').length;
  animateTo('nUnread', unread);
  animateTo('nCrit', crit);
  animateTo('nWarn', warn);
  animateTo('nTotal', NOTIFS.length);
  document.getElementById('unreadCount').textContent = `(${unread})`;
  document.getElementById('sideUnread').textContent = unread;
  if (unread === 0) document.getElementById('sideUnread').style.display = 'none';
  else document.getElementById('sideUnread').style.display = '';
}

function animateTo(id, val){
  const el = document.getElementById(id);
  const cur = parseInt(el.textContent) || 0;
  if (cur === val){ el.textContent = val; return; }
  const start = performance.now();
  const dur = 500;
  (function tick(now){
    const p = Math.min((now-start)/dur, 1);
    const e = 1 - Math.pow(1-p, 3);
    el.textContent = Math.round(cur + (val - cur) * e);
    if (p<1) requestAnimationFrame(tick);
  })(performance.now());
}

function attachActions(){
  // Mark as read → persist by transitioning the underlying alert NEW → INVESTIGATING
  document.querySelectorAll('[data-read]').forEach(b => {
    b.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = parseInt(b.dataset.read);
      const n = NOTIFS.find(x => x.id === id);
      if (!n || !n.unread) return;
      try {
        await AisecAPI.updateAlert(id, 'INVESTIGATING');
        n.unread = false;
        showToast('Marked as read');
        render();
      } catch (err) {
        showToast('Failed to update: ' + err.message);
      }
    });
  });
  // Delete → persist by deleting the alert in DB
  document.querySelectorAll('[data-del]').forEach(b => {
    b.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = parseInt(b.dataset.del);
      const card = b.closest('.notif');
      card.classList.add('removing');
      try {
        await AisecAPI.deleteAlert(id);
        setTimeout(() => {
          NOTIFS = NOTIFS.filter(x => x.id !== id);
          showToast('Notification deleted');
          render();
        }, 320);
      } catch (err) {
        card.classList.remove('removing');
        showToast('Delete failed: ' + err.message);
      }
    });
  });
  // Click card → mark as read (also persists)
  document.querySelectorAll('.notif').forEach(card => {
    card.addEventListener('click', async () => {
      const id = parseInt(card.dataset.id);
      const n = NOTIFS.find(x => x.id === id);
      if (!n || !n.unread) return;
      try {
        await AisecAPI.updateAlert(id, 'INVESTIGATING');
        n.unread = false;
        render();
      } catch { /* ignore — best effort */ }
    });
  });
}

// Tabs
document.querySelectorAll('.n-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.n-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    filter = tab.dataset.filter;
    render();
  });
});

// Mark all as read → persists each alert in DB
document.getElementById('markAllBtn').addEventListener('click', async () => {
  const unread = NOTIFS.filter(n => n.unread);
  if (!unread.length) { showToast('Nothing to mark'); return; }
  showToast(`Marking ${unread.length} as read…`);
  await Promise.allSettled(unread.map(n => AisecAPI.updateAlert(n.id, 'INVESTIGATING')));
  NOTIFS.forEach(n => n.unread = false);
  showToast('All notifications marked as read');
  render();
});

// Clear all → persists deletion in DB
document.getElementById('clearAllBtn').addEventListener('click', async () => {
  if (!NOTIFS.length){ showToast('Already empty'); return; }
  if (!confirm(`Delete all ${NOTIFS.length} alerts permanently?`)) return;
  document.querySelectorAll('.notif').forEach((c, i) => {
    setTimeout(() => c.classList.add('removing'), i*40);
  });
  const ids = NOTIFS.map(n => n.id);
  await Promise.allSettled(ids.map(id => AisecAPI.deleteAlert(id)));
  setTimeout(() => {
    NOTIFS = [];
    showToast('All notifications cleared');
    render();
  }, 400 + NOTIFS.length * 40);
});

// Load more (generate synthetic)
const EXTRA = [
  { type:'info',     icon:'fa-cloud-arrow-up',   title:'Backup Completed',      desc:'Daily backup finished successfully', time:'2 days ago',  unread:false },
  { type:'warning',  icon:'fa-key',              title:'API Key Expiring Soon', desc:'Production API key expires in 7 days', time:'2 days ago',  unread:false },
  { type:'success',  icon:'fa-user-check',       title:'Compliance Check Passed', desc:'Monthly compliance audit completed successfully', time:'3 days ago', unread:false },
  { type:'critical', icon:'fa-user-secret',      title:'Anomalous Access Pattern', desc:'Login from new geolocation for user omar@example.com', time:'3 days ago', unread:false },
];
document.getElementById('loadMore').addEventListener('click', () => {
  const btn = document.getElementById('loadMore');
  btn.classList.add('loading');
  setTimeout(() => {
    const nextId = Math.max(...NOTIFS.map(n => n.id), 0) + 1;
    EXTRA.forEach((e, i) => NOTIFS.push({ id: nextId + i, ...e }));
    visible += EXTRA.length;
    btn.classList.remove('loading');
    render();
    showToast(`${EXTRA.length} more loaded`);
  }, 700);
});

// Toast
const toast = document.getElementById('toast');
function showToast(msg){
  toast.querySelector('span').textContent = msg;
  toast.classList.add('show');
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.remove('show'), 1800);
}

render();

// ===== Backend integration: load notifications from real alerts =====
(async function loadFromBackend(){
  if (!window.AisecAPI) return;
  try {
    const page = await AisecAPI.listAlerts({ size: 50 });
    NOTIFS = (page.content || []).map(alertToNotif);
    render();
  } catch (err) {
    console.warn('[notifications] backend load failed:', err.message);
    render();
  }

  // Debounced full reload to coalesce bursts (e.g. 200 alerts from one PCAP)
  let reloadTimer = null;
  function scheduleReload() {
    clearTimeout(reloadTimer);
    reloadTimer = setTimeout(async () => {
      try {
        const page = await AisecAPI.listAlerts({ size: 50 });
        NOTIFS = (page.content || []).map(alertToNotif);
        render();
      } catch (e) { console.warn('[notifications] reload failed:', e.message); }
    }, 400);
  }

  // Live updates via WebSocket
  try {
    AisecAPI.connectAlertsWS({
      onMessage: (msg) => {
        if (!msg) return;
        if (msg.type === 'alert' && msg.data) {
          NOTIFS.unshift(alertToNotif(msg.data));
          render();
          scheduleReload();
        } else if (msg.type === 'scan_complete') {
          scheduleReload();
        }
      }
    });
  } catch {}
})();
