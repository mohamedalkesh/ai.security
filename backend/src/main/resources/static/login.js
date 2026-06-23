// Password visibility toggle
const toggle = document.querySelector('.toggle-pass');
const pwd = document.getElementById('password');
toggle?.addEventListener('click', () => {
  const isPwd = pwd.type === 'password';
  pwd.type = isPwd ? 'text' : 'password';
  toggle.querySelector('i').className = isPwd ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
});

// Inline error helper
function showAuthError(msg) {
  let bar = document.getElementById('authError');
  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'authError';
    bar.style.cssText = 'background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.4);color:#fecaca;padding:10px 14px;border-radius:8px;margin:0 0 12px;font-size:13px;font-weight:500;display:flex;align-items:center;gap:8px';
    document.querySelector('.auth-form').prepend(bar);
  }
  bar.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${msg}`;
}
function clearAuthError() {
  const bar = document.getElementById('authError');
  if (bar) bar.remove();
}

// Enterprise request modal
const companyModal = document.getElementById('companyModal');
const companyBtn = document.getElementById('companyRequestBtn');
const companyClose = document.getElementById('companyModalClose');
const companyForm = document.getElementById('companyForm');
const companyFeedback = document.getElementById('companyFormFeedback');

function toggleCompanyModal(show) {
  if (!companyModal) return;
  const method = show ? 'add' : 'remove';
  companyModal.classList[method]('active');
  companyModal.setAttribute('aria-hidden', show ? 'false' : 'true');
  if (show) {
    setTimeout(() => {
      document.getElementById('companyName')?.focus();
    }, 150);
  } else {
    companyForm?.reset();
    if (companyFeedback) companyFeedback.textContent = '';
  }
}

companyBtn?.addEventListener('click', () => toggleCompanyModal(true));
companyClose?.addEventListener('click', () => toggleCompanyModal(false));
companyModal?.addEventListener('click', (event) => {
  if (event.target === companyModal) toggleCompanyModal(false);
});

companyForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const name = document.getElementById('companyName')?.value.trim();
  const contact = document.getElementById('companyContact')?.value.trim();
  const email = document.getElementById('companyEmail')?.value.trim();
  const message = document.getElementById('companyMessage')?.value.trim();
  if (!name || !contact || !email) {
    if (companyFeedback) {
      companyFeedback.textContent = 'Please fill company name, contact person and email.';
      companyFeedback.style.color = '#fecaca';
    }
    return;
  }
  if (companyFeedback) {
    companyFeedback.textContent = 'Sending your request…';
    companyFeedback.style.color = '#a5f3fc';
  }
  try {
    await window.AisecAPI.companyRequest({
      companyName: name,
      contactName: contact,
      contactEmail: email,
      notes: message
    });
    if (companyFeedback) {
      companyFeedback.textContent = 'Request delivered! We will email you at ' + email + '.';
      companyFeedback.style.color = '#9ae6b4';
    }
  } catch (err) {
    const msg = err?.message || 'Could not send request right now.';
    if (companyFeedback) {
      companyFeedback.textContent = msg;
      companyFeedback.style.color = '#fecaca';
    }
  }
});

// Already authenticated? Skip login.
if (window.AisecAPI && AisecAPI.isAuthenticated()) {
  window.location.replace('dashboard.html');
}

// Form submit — real backend authentication
const form = document.getElementById('loginForm');
const submitBtn = document.getElementById('submitBtn');
const submitTxt = submitBtn.querySelector('span');
const ICON_DEFAULT = '<i class="fa-solid fa-right-to-bracket"></i>';

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearAuthError();
  const user = document.getElementById('username').value.trim();
  const pass = pwd.value.trim();
  if (!user || !pass) {
    document.querySelector('.auth-card').classList.add('shake');
    setTimeout(() => document.querySelector('.auth-card').classList.remove('shake'), 500);
    return;
  }
  if (!window.AisecAPI) {
    showAuthError('API client not loaded — check api.js');
    return;
  }
  submitBtn.classList.add('loading');
  submitBtn.disabled = true;
  submitTxt.textContent = 'Signing in...';

  // Role the user claimed on the form — must match what backend returns.
  const ROLE_LABEL_TO_BE = {
    'Administrator':       'ADMIN',
    'Organisation Admin':  'ORG_ADMIN',
    'Security Analyst':    'ANALYST',
    'Viewer':              'VIEWER'
  };
  const claimedLabel = document.getElementById('role').value.trim();
  const claimedRole  = ROLE_LABEL_TO_BE[claimedLabel];

  try {
    const data = await AisecAPI.login(user, pass);
    const actualRole = (data.role || '').toUpperCase();

    // SECURITY: reject if the role the user claimed does not match their real role.
    if (!claimedRole || claimedRole !== actualRole) {
      AisecAPI.clearSession();
      submitBtn.classList.remove('loading');
      submitBtn.disabled = false;
      submitTxt.textContent = 'Sign In';
      document.querySelector('.auth-card').classList.add('shake');
      setTimeout(() => document.querySelector('.auth-card').classList.remove('shake'), 500);
      showAuthError('Selected role does not match your account.');
      return;
    }

    submitTxt.innerHTML = 'Success! Redirecting...';
    setTimeout(() => { window.location.href = 'dashboard.html'; }, 600);
  } catch (err) {
    submitBtn.classList.remove('loading');
    submitBtn.disabled = false;
    submitTxt.textContent = 'Sign In';
    document.querySelector('.auth-card').classList.add('shake');
    setTimeout(() => document.querySelector('.auth-card').classList.remove('shake'), 500);
    const msg = err.status === 401 ? 'Invalid username or password'
              : err.status === 0 || err.message.includes('Failed to fetch') ? 'Backend offline — please start it'
              : err.message;
    showAuthError(msg);
  }
});

// Particle network background
const canvas = document.getElementById('particles');
const ctx = canvas.getContext('2d');
let particles = [];
let W, H;

function resize(){
  W = canvas.width = window.innerWidth;
  H = canvas.height = window.innerHeight;
}
resize();
window.addEventListener('resize', resize);

function createParticles(){
  const count = Math.min(80, Math.floor((W * H) / 20000));
  particles = Array.from({length: count}, () => ({
    x: Math.random() * W,
    y: Math.random() * H,
    vx: (Math.random() - 0.5) * 0.4,
    vy: (Math.random() - 0.5) * 0.4,
    r: Math.random() * 1.8 + 0.6
  }));
}
createParticles();

const mouse = { x: -9999, y: -9999 };
window.addEventListener('mousemove', (e) => { mouse.x = e.clientX; mouse.y = e.clientY; });
window.addEventListener('mouseleave', () => { mouse.x = mouse.y = -9999; });

function draw(){
  ctx.clearRect(0, 0, W, H);
  particles.forEach(p => {
    p.x += p.vx; p.y += p.vy;
    if (p.x < 0 || p.x > W) p.vx *= -1;
    if (p.y < 0 || p.y > H) p.vy *= -1;
    ctx.beginPath();
    ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(77,212,232,0.6)';
    ctx.fill();
  });
  // Connect nearby particles
  for (let i = 0; i < particles.length; i++){
    for (let j = i + 1; j < particles.length; j++){
      const a = particles[i], b = particles[j];
      const dx = a.x - b.x, dy = a.y - b.y;
      const d = Math.sqrt(dx*dx + dy*dy);
      if (d < 130){
        ctx.strokeStyle = `rgba(34,184,207,${(1 - d/130) * 0.25})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
      }
    }
    // Mouse interaction
    const dx = particles[i].x - mouse.x, dy = particles[i].y - mouse.y;
    const dm = Math.sqrt(dx*dx + dy*dy);
    if (dm < 160){
      ctx.strokeStyle = `rgba(77,212,232,${(1 - dm/160) * 0.5})`;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(particles[i].x, particles[i].y); ctx.lineTo(mouse.x, mouse.y); ctx.stroke();
    }
  }
  requestAnimationFrame(draw);
}
draw();
