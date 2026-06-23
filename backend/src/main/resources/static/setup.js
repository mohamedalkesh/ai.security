let current = 1;
let testPassed = false;
const TOTAL = 5;

const steps = document.querySelectorAll('.stp');
const lines = document.querySelectorAll('.stp-line');
const panels = document.querySelectorAll('.step-panel');

const backBtn = document.getElementById('backBtn');
const nextBtn = document.getElementById('nextBtn');
const stepNum = document.getElementById('stepNum');

function render(){
  steps.forEach(s => {
    const n = parseInt(s.dataset.n);
    s.classList.toggle('active', n === current);
    s.classList.toggle('done', n < current);
  });
  lines.forEach((l, i) => {
    l.classList.toggle('done', i < current - 1);
  });
  panels.forEach(p => p.classList.toggle('active', parseInt(p.dataset.step) === current));
  stepNum.textContent = current;

  backBtn.disabled = current === 1;

  // Next button logic
  if (current === 4){
    nextBtn.disabled = !testPassed;
  } else if (current === TOTAL){
    nextBtn.innerHTML = 'Start Monitoring <i class="fa-solid fa-arrow-right"></i>';
    nextBtn.disabled = false;
  } else {
    nextBtn.innerHTML = 'Next <i class="fa-solid fa-arrow-right"></i>';
    nextBtn.disabled = false;
  }
}

function renderConfigForm(){
  const method = document.querySelector('input[name="method"]:checked')?.value || 'sniffer';
  const form = document.getElementById('configForm');
  if (method === 'sniffer'){
    form.innerHTML = `
      <label><span>Network Interface</span>
        <select>
          <option>eth0 - Primary Interface</option>
          <option>eth1 - Secondary Interface</option>
          <option>wlan0 - Wireless Interface</option>
          <option>bond0 - Bonded Interface</option>
        </select>
      </label>
    `;
  } else if (method === 'syslog'){
    form.innerHTML = `
      <label><span>Syslog Server Address</span><input type="text" value="192.168.1.10" placeholder="IP or hostname"/></label>
      <label><span>Port</span><input type="text" value="514"/></label>
      <label><span>Protocol</span>
        <select><option>UDP</option><option>TCP</option><option>TLS</option></select>
      </label>
    `;
  } else {
    form.innerHTML = `
      <label><span>API Endpoint URL</span><input type="text" value="https://api.example.com/v1/logs" placeholder="https://..."/></label>
      <label><span>API Key</span><input type="text" value="sk_live_••••••••••••4721"/></label>
      <label><span>Poll Interval (seconds)</span><input type="text" value="30"/></label>
    `;
  }
}

// Back / Next
backBtn.addEventListener('click', () => {
  if (current > 1){ current--; testPassed = false; render(); }
});
nextBtn.addEventListener('click', () => {
  if (current === TOTAL){
    // Start monitoring → go to dashboard
    nextBtn.disabled = true;
    nextBtn.innerHTML = '<i class="fa-solid fa-spinner spin"></i> Launching...';
    setTimeout(() => { window.location.href = 'dashboard.html'; }, 900);
    return;
  }
  // animate the line between current and next
  const line = lines[current - 1];
  if (line) line.classList.add('animating');
  setTimeout(() => {
    current++;
    if (current === 3) renderConfigForm();
    render();
  }, 200);
});

// Method change → rebuild config form next time
document.querySelectorAll('input[name="method"]').forEach(r => {
  r.addEventListener('change', () => renderConfigForm());
});

// Test Connection
const testBtn = document.getElementById('testBtn');
const testLog = document.getElementById('testLog');
testBtn.addEventListener('click', () => {
  testBtn.disabled = true;
  testBtn.classList.add('testing');
  testBtn.innerHTML = '<i class="fa-solid fa-spinner"></i> Testing...';
  testLog.hidden = false;
  testLog.innerHTML = '';

  const logs = [
    { msg:'→ Resolving network interface...', cls:'info', delay:300 },
    { msg:'✓ Interface eth0 detected', cls:'ok',   delay:600 },
    { msg:'→ Checking permissions...',       cls:'info', delay:900 },
    { msg:'✓ Packet capture enabled',        cls:'ok',   delay:1300 },
    { msg:'→ Contacting AI engine...',       cls:'info', delay:1600 },
    { msg:'✓ AI engine responsive',          cls:'ok',   delay:2000 },
    { msg:'✓ Connection successful',         cls:'ok',   delay:2300 },
  ];

  logs.forEach(l => {
    setTimeout(() => {
      const line = document.createElement('div');
      line.className = 'log-line ' + l.cls;
      line.textContent = l.msg;
      testLog.appendChild(line);
      testLog.scrollTop = testLog.scrollHeight;
    }, l.delay);
  });

  setTimeout(() => {
    testBtn.classList.remove('testing');
    testBtn.classList.add('done');
    testBtn.innerHTML = '<i class="fa-solid fa-check"></i> Connection OK';
    testPassed = true;
    render();
    showToast('Connection test passed');
  }, 2500);
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
