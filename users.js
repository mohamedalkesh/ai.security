// Reveal
const io = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting){ e.target.classList.add('visible'); io.unobserve(e.target); }});
}, { threshold:.08 });
document.querySelectorAll('.reveal').forEach(el => io.observe(el));

// Require auth
if (window.AisecAPI) AisecAPI.requireAuth();

// ===== Role mapping (frontend ↔ backend) =====
// Backend roles: ADMIN, ORG_ADMIN, ANALYST, VIEWER
function feToBe(role) {
  const m = { administrator:'ADMIN', org_admin:'ORG_ADMIN', analyst:'ANALYST', viewer:'VIEWER' };
  return m[role] || 'VIEWER';
}
function beToFe(role) {
  const m = { ADMIN:'administrator', ORG_ADMIN:'org_admin', ANALYST:'analyst', VIEWER:'viewer' };
  return m[role] || 'viewer';
}
const ROLE_LABELS = {
  administrator: 'Administrator',
  org_admin:     'Org Admin',
  analyst:       'Security Analyst',
  viewer:        'Viewer'
};
const COLORS = ['c1','c2','c3','c4','c5'];

let USERS = [];
let ORGS  = [];
let search = '';

// True only when the logged-in user is the system ADMIN (no org).
const IS_SYS_ADMIN = !!(window.AisecAPI &&
  AisecAPI.getRole && AisecAPI.getRole() === 'ADMIN' &&
  (!AisecAPI.getOrgId || AisecAPI.getOrgId() == null));

async function loadOrgs() {
  if (!IS_SYS_ADMIN) return;
  try {
    ORGS = await AisecAPI.listOrganizations();
    const sel = document.getElementById('fOrg');
    // Keep the first option (“System (no org)”), append all real orgs.
    sel.innerHTML = '<option value="">— System (no org) —</option>' +
      ORGS.map(o => `<option value="${o.id}">${o.name}</option>`).join('');
  } catch (e) {
    console.warn('Failed to load organisations:', e.message);
  }
}

// Show/hide org selector and align it with the chosen role.
function syncOrgFieldWithRole() {
  if (!IS_SYS_ADMIN) return;            // org admins never see the org selector
  const role = document.getElementById('fRole').value;
  const isSysRole = (role === 'administrator');
  const row = document.getElementById('fOrgRow');
  const sel = document.getElementById('fOrg');
  row.style.display = '';               // always shown for system admin
  if (isSysRole) {
    sel.value = '';                     // ADMIN → must be system tenant
    sel.disabled = true;
  } else {
    sel.disabled = false;
    if (!sel.value && ORGS.length) sel.value = String(ORGS[0].id);
  }
}

function initials(name){
  return (name || '?').split(/\s+/).map(p => p[0]).slice(0,2).join('').toUpperCase();
}
function timeAgo(iso) {
  if (!iso) return 'Never';
  const t = new Date(iso).getTime();
  const diff = (Date.now() - t) / 1000;
  if (diff < 60)    return Math.floor(diff) + ' sec ago';
  if (diff < 3600)  return Math.floor(diff/60) + ' min ago';
  if (diff < 86400) return Math.floor(diff/3600) + ' hour ago';
  return Math.floor(diff/86400) + ' day ago';
}

function setBanner(text, kind) {
  let bar = document.getElementById('usersBanner');
  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'usersBanner';
    bar.style.cssText = 'padding:10px 14px;border-radius:8px;margin:0 0 14px;font-size:13px;font-weight:500';
    document.querySelector('.toolbar-panel')?.before(bar);
  }
  if (!text) { bar.style.display = 'none'; return; }
  bar.style.display = 'block';
  const colors = {
    info:    'background:rgba(34,184,207,.15);border:1px solid rgba(34,184,207,.4);color:#a5f3fc',
    error:   'background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.4);color:#fecaca',
    success: 'background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.4);color:#bbf7d0',
    warn:    'background:rgba(251,191,36,.12);border:1px solid rgba(251,191,36,.4);color:#fde68a'
  };
  bar.style.cssText += ';' + (colors[kind] || colors.info);
  bar.textContent = text;
}

function render(){
  const filtered = USERS.filter(u => {
    const q = search.toLowerCase();
    return !q || (u.fullName||'').toLowerCase().includes(q) ||
                 (u.email||'').toLowerCase().includes(q) ||
                 (u.role||'').toLowerCase().includes(q);
  });
  const body = document.getElementById('usersBody');
  body.innerHTML = filtered.map((u, i) => {
    const feRole = beToFe(u.role);
    const color = COLORS[(u.id - 1) % COLORS.length];
    return `
    <tr style="animation-delay:${i*.04}s" data-id="${u.id}">
      <td>
        <div class="user-cell">
          <div class="u-avatar ${color}">${initials(u.fullName)}</div>
          <div><div class="u-name">${u.fullName}</div><div class="u-email">${u.email}</div></div>
        </div>
      </td>
      <td><span class="role-chip ${feRole}">${ROLE_LABELS[feRole]}</span></td>
      <td><span class="u-status ${u.enabled?'active':'inactive'}">${u.enabled?'Active':'Inactive'}</span></td>
      <td class="muted">${timeAgo(u.lastLoginAt)}</td>
      <td class="right">
        <div class="u-actions">
          <button class="act-btn edit" title="Edit role" data-edit="${u.id}" data-requires-role="ADMIN,ORG_ADMIN"><i class="fa-solid fa-pen"></i></button>
          <button class="act-btn del" title="Delete"   data-del="${u.id}" data-requires-role="ADMIN,ORG_ADMIN"><i class="fa-solid fa-trash"></i></button>
        </div>
      </td>
    </tr>`;
  }).join('') || `<tr><td colspan="5" style="text-align:center;padding:40px;color:var(--muted)">No users found</td></tr>`;

  document.getElementById('stTotal').textContent    = USERS.length;
  document.getElementById('stActive').textContent   = USERS.filter(u => u.enabled).length;
  document.getElementById('stInactive').textContent = USERS.filter(u => !u.enabled).length;

  body.querySelectorAll('[data-edit]').forEach(b =>
    b.addEventListener('click', (e) => { e.stopPropagation(); openEdit(parseInt(b.dataset.edit)); }));
  body.querySelectorAll('[data-del]').forEach(b =>
    b.addEventListener('click', (e) => { e.stopPropagation(); openDelete(parseInt(b.dataset.del)); }));

  // Re-apply RBAC on the newly rendered rows
  if (window.AisecAPI && AisecAPI.applyRbac) AisecAPI.applyRbac(body);
}

document.getElementById('usearch').addEventListener('input', (e) => { search = e.target.value; render(); });

// ===== Modals =====
const userModal = document.getElementById('userModal');
const delModal  = document.getElementById('delModal');
let editId = null, delId = null;

// Password visibility toggles
document.getElementById('toggleFPass').addEventListener('click', () => togglePassVis('fPass', 'toggleFPass'));
document.getElementById('toggleFConfirm').addEventListener('click', () => togglePassVis('fConfirm', 'toggleFConfirm'));
function togglePassVis(inputId, btnId) {
  const inp = document.getElementById(inputId);
  const ic  = document.querySelector('#' + btnId + ' i');
  inp.type = inp.type === 'password' ? 'text' : 'password';
  ic.className = inp.type === 'text' ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
}

function setPassFieldsVisible(show) {
  ['fUsernameRow','fPassRow','fConfirmRow'].forEach(id => {
    document.getElementById(id).style.display = show ? '' : 'none';
  });
}

function openAdd(){
  editId = null;
  document.getElementById('umMode').textContent = 'NEW USER';
  document.getElementById('umTitle').textContent = 'Add User';
  document.querySelector('#userModal .modal-ico i').className = 'fa-solid fa-user-plus';
  document.getElementById('fName').value    = '';
  document.getElementById('fEmail').value   = '';
  document.getElementById('fUsername').value = '';
  document.getElementById('fPass').value    = '';
  document.getElementById('fConfirm').value = '';
  document.getElementById('fRole').value    = IS_SYS_ADMIN ? 'org_admin' : 'analyst';
  document.getElementById('fStatus').value  = 'active';
  document.getElementById('umError').style.display = 'none';
  setPassFieldsVisible(true);
  syncOrgFieldWithRole();
  userModal.classList.add('show');
  setTimeout(() => document.getElementById('fName').focus(), 100);
}
function openEdit(id){
  editId = id;
  const u = USERS.find(x => x.id === id); if (!u) return;
  document.getElementById('umMode').textContent = 'EDIT';
  document.getElementById('umTitle').textContent = 'Edit User Role';
  document.querySelector('#userModal .modal-ico i').className = 'fa-solid fa-user-pen';
  document.getElementById('fName').value  = u.fullName;
  document.getElementById('fEmail').value = u.email;
  document.getElementById('fRole').value  = beToFe(u.role);
  document.getElementById('fStatus').value = u.enabled ? 'active' : 'inactive';
  document.getElementById('umError').style.display = 'none';
  document.getElementById('fName').disabled = true;
  document.getElementById('fEmail').disabled = true;
  document.getElementById('fStatus').disabled = true;
  setPassFieldsVisible(false);
  userModal.classList.add('show');
}
function openDelete(id){
  delId = id;
  const u = USERS.find(x => x.id === id);
  document.getElementById('delName').textContent = u.fullName;
  delModal.classList.add('show');
}
function closeAll(){
  userModal.classList.remove('show'); delModal.classList.remove('show');
  document.getElementById('fName').disabled    = false;
  document.getElementById('fEmail').disabled   = false;
  document.getElementById('fStatus').disabled  = false;
  document.getElementById('umError').style.display = 'none';
  setPassFieldsVisible(true);
}

document.getElementById('addUserBtn').addEventListener('click', openAdd);
document.getElementById('fRole').addEventListener('change', syncOrgFieldWithRole);
document.getElementById('closeUser').addEventListener('click', closeAll);
document.getElementById('cancelUser').addEventListener('click', closeAll);
document.getElementById('cancelDel').addEventListener('click', closeAll);
[userModal, delModal].forEach(m => m.addEventListener('click', (e) => { if (e.target === m) closeAll(); }));
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeAll(); });

document.getElementById('saveUser').addEventListener('click', async () => {
  const name = document.getElementById('fName').value.trim();
  const email = document.getElementById('fEmail').value.trim();
  const role = document.getElementById('fRole').value;
  if (editId) {
    // Update role only
    try {
      const updated = await AisecAPI.changeRole(editId, feToBe(role));
      const idx = USERS.findIndex(x => x.id === editId);
      if (idx >= 0) USERS[idx] = updated;
      showToast(`✓ ${updated.fullName} role updated to ${updated.role}`);
      closeAll();
      render();
    } catch (err) {
      showToast('Update failed: ' + err.message);
    }
  } else {
    const username = document.getElementById('fUsername').value.trim();
    const password = document.getElementById('fPass').value;
    const confirm  = document.getElementById('fConfirm').value;
    const errEl    = document.getElementById('umError');

    if (!name || !email || !username) { showUmError('Please fill in all fields.'); return; }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { showUmError('Invalid email address.'); return; }
    if (password.length < 8) { showUmError('Password must be at least 8 characters.'); return; }
    if (password !== confirm) { showUmError('Passwords do not match.'); return; }

    const saveBtn = document.getElementById('saveUser');
    saveBtn.disabled = true;
    saveBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Creating…';
    errEl.style.display = 'none';
    // System admin must pick an org for non-ADMIN roles; org admin inherits.
    let organizationId = null;
    if (IS_SYS_ADMIN) {
      const v = document.getElementById('fOrg').value;
      organizationId = v ? Number(v) : null;
      if (feToBe(role) !== 'ADMIN' && organizationId == null) {
        showUmError('Please select an organisation for this role.');
        return;
      }
      if (feToBe(role) === 'ADMIN' && organizationId != null) {
        showUmError('System administrators cannot belong to an organisation.');
        return;
      }
    }

    try {
      // Atomic create: backend assigns role + org in one transaction.
      await AisecAPI.createUser({
        username, email, full_name: name, password,
        role: feToBe(role),
        organizationId
      });
      await load();
      // Send welcome email
      try {
        await AisecAPI.sendWelcomeEmail({ email, fullName: name, username, password });
      } catch (mailErr) {
        console.warn('Welcome email failed:', mailErr.message);
      }
      showToast(`✓ ${name} added — welcome email sent to ${email}`);
      closeAll();
    } catch (err) {
      showUmError(err.message || 'Failed to add user.');
    } finally {
      saveBtn.disabled = false;
      saveBtn.innerHTML = '<i class="fa-solid fa-check"></i> Save';
    }
  }
});

document.getElementById('confirmDel').addEventListener('click', async () => {
  const u = USERS.find(x => x.id === delId);
  try {
    await AisecAPI.deleteUser(delId);
    USERS = USERS.filter(x => x.id !== delId);
    showToast(`${u.fullName} deleted`);
    closeAll();
    render();
  } catch (err) {
    showToast('Delete failed: ' + err.message);
  }
});

function showUmError(msg) {
  const el = document.getElementById('umError');
  el.textContent = msg; el.style.display = 'block';
}

// Toast
const toast = document.getElementById('toast');
function showToast(msg){
  toast.querySelector('span').textContent = msg;
  toast.classList.add('show');
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.remove('show'), 2500);
}

// ===== Load from backend =====
async function load() {
  if (!window.AisecAPI) {
    setBanner('API client not loaded', 'error');
    return;
  }
  try {
    setBanner('Loading users from backend…', 'info');
    USERS = await AisecAPI.listUsers();
    setBanner(`Loaded ${USERS.length} users from PostgreSQL`, 'success');
    setTimeout(() => setBanner(''), 2500);
    render();
  } catch (err) {
    if (err.status === 403) {
      setBanner('Access denied — Users page requires ANALYST or ADMIN role', 'warn');
    } else {
      setBanner('Failed to load users: ' + err.message, 'error');
    }
    render();
  }
}
load();
loadOrgs();
