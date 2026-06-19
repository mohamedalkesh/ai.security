// Backend auth guard
if (window.AisecAPI) AisecAPI.requireAuth();

// Reveal
const io = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting){ e.target.classList.add('visible'); io.unobserve(e.target); }});
}, { threshold:.08 });
document.querySelectorAll('.reveal').forEach(el => io.observe(el));

// ===== DOM handles =====
const sens     = document.getElementById('sens');
const sensVal  = document.getElementById('sensVal');
const textInputs  = document.querySelectorAll('.set-field input[type="text"]');   // [systemName, organization]
const selects    = document.querySelectorAll('.set-field select');                // [timezone, aiModel]
const checkboxes = document.querySelectorAll('input[type="checkbox"][data-setting]');

// Map between DOM setting keys and backend JSON structure
const SECURITY_KEYS = { '2fa':'twoFactor', 'ip':'ipWhitelist', 'lockout':'autoLockout' };
const NOTIF_KEYS    = { 'email':'email',   'sms':'sms',       'slack':'slack' };
const AI_KEYS       = { 'autoclass':'autoClassify' };

// ===== Detection sensitivity slider =====
function updateSlider(){
  const v = sens.value;
  sensVal.textContent = v + '%';
  sens.style.background = `linear-gradient(90deg, var(--primary) 0%, var(--primary) ${v}%, rgba(255,255,255,.08) ${v}%, rgba(255,255,255,.08) 100%)`;
}
sens.addEventListener('input', updateSlider);
updateSlider();

// ===== Toggle feedback =====
checkboxes.forEach(cb => {
  cb.addEventListener('change', () => {
    const row = cb.closest('.toggle-row');
    const title = row.querySelector('.tr-title').textContent;
    showToast(`${title} ${cb.checked ? 'enabled' : 'disabled'} (not saved yet)`);
  });
});

// ===== Collect current form state → backend shape =====
function collectPayload() {
  const security = {};
  const notif = {};
  const ai = {};
  checkboxes.forEach(cb => {
    const k = cb.dataset.setting;
    if (SECURITY_KEYS[k]) security[SECURITY_KEYS[k]] = cb.checked;
    else if (NOTIF_KEYS[k]) notif[NOTIF_KEYS[k]] = cb.checked;
    else if (AI_KEYS[k]) ai[AI_KEYS[k]] = cb.checked;
  });
  ai.sensitivity = parseInt(sens.value, 10);
  ai.model       = selects[1] ? selects[1].value : 'SecurityNet-AI v3.2 (Latest)';

  return {
    general: {
      systemName:   textInputs[0] ? textInputs[0].value : '',
      organization: textInputs[1] ? textInputs[1].value : '',
      timezone:     selects[0] ? selects[0].value : ''
    },
    security,
    ai,
    notifications: notif
  };
}

// ===== Apply backend payload → form =====
function applyPayload(p) {
  if (!p) return;
  if (p.general) {
    if (textInputs[0] && p.general.systemName != null)   textInputs[0].value = p.general.systemName;
    if (textInputs[1] && p.general.organization != null) textInputs[1].value = p.general.organization;
    if (selects[0] && p.general.timezone != null) {
      const opt = [...selects[0].options].find(o => o.value === p.general.timezone || o.textContent === p.general.timezone);
      if (opt) selects[0].value = opt.value;
    }
  }
  checkboxes.forEach(cb => {
    const k = cb.dataset.setting;
    if (SECURITY_KEYS[k] && p.security && p.security[SECURITY_KEYS[k]] != null)   cb.checked = !!p.security[SECURITY_KEYS[k]];
    else if (NOTIF_KEYS[k] && p.notifications && p.notifications[NOTIF_KEYS[k]] != null) cb.checked = !!p.notifications[NOTIF_KEYS[k]];
    else if (AI_KEYS[k] && p.ai && p.ai[AI_KEYS[k]] != null)                    cb.checked = !!p.ai[AI_KEYS[k]];
  });
  if (p.ai) {
    if (p.ai.sensitivity != null) { sens.value = p.ai.sensitivity; updateSlider(); }
    if (p.ai.model != null && selects[1]) {
      const opt = [...selects[1].options].find(o => o.textContent === p.ai.model || o.value === p.ai.model);
      if (opt) selects[1].value = opt.value;
    }
  }
}

// ===== localStorage helpers =====
const LS_KEY = 'aisec_settings';
function saveLocal(payload) {
  try { localStorage.setItem(LS_KEY, JSON.stringify(payload)); } catch {}
}
function loadLocal() {
  try { return JSON.parse(localStorage.getItem(LS_KEY) || 'null'); } catch { return null; }
}

// ===== Load on init =====
(async function loadSettings(){
  // 1. Apply localStorage immediately (fast, no flicker)
  const local = loadLocal();
  if (local) applyPayload(local);

  if (!window.AisecAPI) return;
  try {
    const resp = await AisecAPI.getSettings();
    const payload = resp.settings || resp;
    applyPayload(payload);
    saveLocal(payload); // keep localStorage in sync
    if (resp.updatedAt) {
      console.log('[settings] loaded from server, updated at', resp.updatedAt, 'by', resp.updatedBy || 'system');
    }
  } catch (err) {
    console.warn('[settings] server load failed, using localStorage:', err.message);
  }
})();

// ===== Save =====
const overlay = document.getElementById('saveOverlay');
const saveBtn = document.getElementById('saveBtn');
saveBtn.addEventListener('click', async () => {
  if (!window.AisecAPI) { overlay.classList.add('show'); setTimeout(() => overlay.classList.remove('show'), 1400); return; }
  const payload = collectPayload();
  saveBtn.disabled = true;
  // Always save to localStorage first
  saveLocal(payload);
  try {
    await AisecAPI.updateSettings(payload);
    overlay.classList.add('show');
    setTimeout(() => overlay.classList.remove('show'), 1400);
    showToast('Settings saved');
  } catch (err) {
    // Show overlay anyway — local save succeeded
    overlay.classList.add('show');
    setTimeout(() => overlay.classList.remove('show'), 1400);
    if (err.status === 403) {
      showToast('Saved locally (server: Admin only)');
    } else {
      showToast('Saved locally (server offline)');
    }
  } finally {
    saveBtn.disabled = false;
  }
});

// ===== Reset =====
document.getElementById('resetBtn').addEventListener('click', async () => {
  if (window.AisecAPI) {
    try {
      const resp = await AisecAPI.resetSettings();
      applyPayload(resp.settings || resp);
      showToast('Settings reset to default');
      return;
    } catch (err) {
      if (err.status === 403) { showToast('Forbidden: only ADMIN can reset settings'); return; }
      console.warn('[settings] reset failed, using local defaults:', err.message);
    }
  }
  // Local fallback
  checkboxes.forEach(cb => {
    const defaults = { '2fa':true, 'ip':false, 'lockout':true, 'autoclass':true, 'email':true, 'sms':true, 'slack':false };
    cb.checked = defaults[cb.dataset.setting] || false;
  });
  sens.value = 75;
  updateSlider();
  showToast('Settings reset to default (local only)');
});

// ===== Export =====

// ===== Toast =====
const toast = document.getElementById('toast');
function showToast(msg){
  toast.querySelector('span').textContent = msg;
  toast.classList.add('show');
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.remove('show'), 2200);
}
