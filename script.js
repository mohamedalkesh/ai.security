// Scroll-triggered reveal animations
const revealEls = document.querySelectorAll('.reveal');
const io = new IntersectionObserver((entries) => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      e.target.classList.add('visible');
      // Animate counters once visible
      const num = e.target.querySelector('.stat-num[data-target]');
      if (num && !num.dataset.done) animateCount(num);
      io.unobserve(e.target);
    }
  });
}, { threshold: 0.15 });
revealEls.forEach(el => io.observe(el));

// Stagger feature cards
document.querySelectorAll('.features-grid .reveal').forEach((el, i) => {
  el.style.transitionDelay = (i * 80) + 'ms';
});
document.querySelectorAll('.stats-grid .reveal').forEach((el, i) => {
  el.style.transitionDelay = (i * 100) + 'ms';
});
document.querySelectorAll('.footer-grid .reveal').forEach((el, i) => {
  el.style.transitionDelay = (i * 100) + 'ms';
});

// Counter animation
function animateCount(el){
  el.dataset.done = '1';
  const target = parseFloat(el.dataset.target);
  const suffix = el.dataset.suffix || '';
  const duration = 1400;
  const start = performance.now();
  const isFloat = target % 1 !== 0;
  function tick(now){
    const p = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - p, 3);
    const val = target * ease;
    el.textContent = (isFloat ? val.toFixed(1) : Math.floor(val)) + suffix;
    if (p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// Nav shadow & back-to-top
const nav = document.querySelector('.nav');
const toTop = document.getElementById('toTop');
window.addEventListener('scroll', () => {
  const y = window.scrollY;
  nav.classList.toggle('scrolled', y > 20);
  toTop.classList.toggle('show', y > 500);
});
toTop.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));

// Parallax on hero bg
const heroBg = document.querySelector('.hero-bg');
if (heroBg){
  window.addEventListener('scroll', () => {
    const y = window.scrollY;
    if (y < 800) heroBg.style.transform = `translateY(${y * 0.3}px)`;
  });
}
