// Reveal
const io = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting){ e.target.classList.add('visible'); io.unobserve(e.target); }});
}, { threshold:.08 });
document.querySelectorAll('.reveal').forEach(el => io.observe(el));

// Form submit
const form = document.getElementById('contactForm');
const overlay = document.getElementById('sentOverlay');
form.addEventListener('submit', (e) => {
  e.preventDefault();
  const name = document.getElementById('cName').value.trim();
  const email = document.getElementById('cEmail').value.trim();
  const msg = document.getElementById('cMsg').value.trim();
  if (!name || !email || !msg){ showToast('Please fill all required fields'); return; }

  const btn = form.querySelector('.send-btn');
  const originalHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner spin"></i> Sending...';

  setTimeout(() => {
    overlay.classList.add('show');
    setTimeout(() => {
      overlay.classList.remove('show');
      btn.disabled = false;
      btn.innerHTML = originalHtml;
      document.getElementById('cMsg').value = '';
    }, 1800);
  }, 1000);
});

// Emergency call — opens WhatsApp
document.getElementById('emBtn').addEventListener('click', () => {
  window.open('https://wa.me/218944415044', '_blank');
});

// Quick links feedback
document.querySelectorAll('.quick-links a').forEach(a => {
  a.addEventListener('click', (e) => {
    e.preventDefault();
    showToast(a.textContent.trim() + ' opened');
  });
});

// Toast
const toast = document.getElementById('toast');
function showToast(msg){
  toast.querySelector('span').textContent = msg;
  toast.classList.add('show');
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.remove('show'), 1800);
}
