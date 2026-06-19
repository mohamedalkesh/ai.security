// ===== PCAP Scan page =====
if (window.AisecAPI) AisecAPI.requireAuth();

// Reveal animations
const io = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting){ e.target.classList.add('visible'); io.unobserve(e.target); }});
}, { threshold:.1 });
document.querySelectorAll('.reveal').forEach(el => io.observe(el));

// ===== Element refs =====
const dropZone   = document.getElementById('dropZone');
const fileInput  = document.getElementById('fileInput');
const browseBtn  = document.getElementById('browseBtn');
const progPanel  = document.getElementById('progressPanel');
const progBar    = document.getElementById('progBar');
const progText   = document.getElementById('progText');
const resultsSec = document.getElementById('resultsSection');
const resetBtn   = document.getElementById('resetBtn');
const toast      = document.getElementById('toast');

let activeScanId = null;
let scanPollTimer = null;
let scanWs = null;
// Polling is now only a fallback; the WebSocket delivers the result instantly.
const POLL_INTERVAL_MS = 2000;

// ===== Toast =====
function showToast(msg, isError) {
  toast.querySelector('span').textContent = msg;
  toast.classList.add('show');
  toast.style.background = isError ? '#ff6b6b' : '';
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.remove('show'), 2500);
}

// ===== Drag & drop =====
['dragenter','dragover'].forEach(ev =>
  dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.add('dragover'); }));
['dragleave','drop'].forEach(ev =>
  dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.remove('dragover'); }));

dropZone.addEventListener('drop', (e) => {
  const file = e.dataTransfer.files[0];
  if (file) handleFile(file);
});
dropZone.addEventListener('click', (e) => {
  if (e.target.closest('button')) return;
  fileInput.click();
});
browseBtn.addEventListener('click', (e) => { e.stopPropagation(); fileInput.click(); });
fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) handleFile(fileInput.files[0]);
});

// ===== Stage helpers =====
function setStage(name, state) {
  // state: 'active' | 'done'
  const el = document.querySelector(`.prog-step[data-stage="${name}"]`);
  if (!el) return;
  el.classList.remove('active','done');
  if (state) el.classList.add(state);
}
function setProgress(pct, text) {
  progBar.style.width = pct + '%';
  if (text) progText.textContent = text;
}
function resetStages() {
  ['upload','analyze','save'].forEach(s => setStage(s, null));
  setProgress(0, 'Waiting…');
}
function clearScanPoll() {
  if (scanPollTimer) {
    clearInterval(scanPollTimer);
    scanPollTimer = null;
  }
}

// ===== Live scan updates via WebSocket (instant, no polling lag) =====
function connectScanWs() {
  if (scanWs || !window.AisecAPI || !AisecAPI.connectAlertsWS) return;
  scanWs = AisecAPI.connectAlertsWS({
    onMessage: (msg) => {
      if (!msg || msg.type !== 'scan_complete' || !msg.data) return;
      const scan = msg.data;
      // Only react to the scan we're actively tracking; refresh the recent
      // table for any other completed scan in this tenant.
      if (activeScanId != null && String(scan.id) === String(activeScanId)) {
        applyScanUpdate(scan);
      } else {
        loadRecent();
      }
    },
    onError: () => {} // silent — the poll fallback keeps things working
  });
}

// Single source of truth for reacting to a terminal scan state, whether it
// arrives via WebSocket push or the polling fallback.
function applyScanUpdate(scan) {
  if (!scan) return;
  const status = (scan.status || '').toUpperCase();
  if (status === 'PROCESSING') {
    setStage('analyze', 'active');
    setProgress(65, 'AI engine crunching flows… this may take a moment');
    return;
  }

  clearScanPoll();
  if (status === 'FAILED') {
    setStage('analyze', 'done');
    setProgress(100, '✗ Scan failed');
    progBar.style.background = '#ff6b6b';
    showToast('Scan failed: ' + (scan.error_message || 'unknown'), true);
    return;
  }

  setStage('analyze', 'done');
  setStage('save', 'active');
  setProgress(90, 'Saving alerts…');
  setStage('save', 'done');
  setProgress(100, '✓ Scan complete');
  renderResults(scan);
  loadRecent();
  showToast(`Scan finished: ${scan.attack_count || 0} attacks found`);
}

// ===== Main upload handler =====
const MAX_BYTES = 2560 * 1024 * 1024; // 2.5 GB

async function handleFile(file) {
  // Validate size only — backend handles content type.
  if (file.size > MAX_BYTES) {
    showToast(`File too large (${(file.size/1024/1024).toFixed(1)} MB > 2560 MB / 2.5 GB)`, true);
    return;
  }

  // UI: show progress, hide results
  resultsSec.style.display = 'none';
  progPanel.style.display = '';
  resetStages();
  progBar.style.background = 'linear-gradient(90deg,#22b8cf,#9775fa)';
  clearScanPoll();
  activeScanId = null;
  setStage('upload', 'active');
  setProgress(15, `Uploading "${file.name}" (${(file.size/1024/1024).toFixed(2)} MB)…`);

  try {
    const kickOff = await AisecAPI.predictPcap(file);
    activeScanId = kickOff.id;

    setStage('upload', 'done');
    setStage('analyze', 'active');
    setProgress(45, 'AI engine analyzing flows… (feel free to keep browsing)');

    showToast('Scan started — you can navigate away; progress will continue.');
    monitorScan(activeScanId);
  } catch (err) {
    console.error(err);
    setProgress(100, '✗ Scan failed');
    progBar.style.background = '#ff6b6b';
    showToast('Upload failed: ' + (err.message || 'unknown'), true);
    setTimeout(() => { progPanel.style.display = 'none'; }, 2500);
  }
}

async function monitorScan(scanId) {
  if (!scanId) return;
  connectScanWs();              // instant push path
  await fetchScanStatus(scanId); // immediate first check
  clearScanPoll();
  scanPollTimer = setInterval(() => fetchScanStatus(scanId, true), POLL_INTERVAL_MS);
}

async function fetchScanStatus(scanId, silent) {
  try {
    const scan = await AisecAPI.getScan(scanId);
    applyScanUpdate(scan);
  } catch (err) {
    if (!silent) {
      console.error(err);
      showToast('Failed to refresh scan status: ' + (err.message || 'unknown'), true);
    }
  }
}

// ===== Render results =====
function renderResults(r) {
  resultsSec.style.display = '';
  setText('rTotal',   (r.total_flows  || 0).toLocaleString());
  setText('rBenign',  (r.benign_count || 0).toLocaleString());
  setText('rAttacks', (r.attack_count || 0).toLocaleString());
  const conf = (r.avg_confidence || 0) * 100;
  setText('rConf', conf.toFixed(1));

  // Parse summary if present (string JSON in summary_json)
  let breakdown = {};
  try {
    const raw = r.summary_json ? JSON.parse(r.summary_json) : (r.summary || {});
    // ML returns flat {ClassName: count}; nested forms are also handled
    breakdown = raw.attack_breakdown || raw.breakdown || raw;
  } catch {}

  // Sampled / truncated warning
  const sampledBanner = document.getElementById('sampledBanner');
  const sampledFlag = r.sampled ?? r.sampled_flag ?? r.sampled_csv;
  const originalRows = r.original_rows ?? r.originalRows ?? r.original_count;
  const sampledRows = r.sampled_rows ?? r.sampledRows ?? r.sampled_count;
  if (sampledBanner) {
    if (sampledFlag) {
      sampledBanner.style.display = '';
      const isPcap = (r.source_type || '').toUpperCase() === 'PCAP';
      if (isPcap) {
        sampledBanner.innerHTML = `⚠️ الملف كبير جداً — تم تحليل أول <strong>${(sampledRows||0).toLocaleString()}</strong> تدفق فقط. الهجمات المحتملة في باقي الملف لم تُحلَّل.`;
      } else {
        sampledBanner.innerHTML = `⚠️ الملف كبير جداً — تم تحليل <strong>${(sampledRows||0).toLocaleString()}</strong> صف من أصل <strong>${(originalRows||0).toLocaleString()}</strong> صف.`;
      }
    } else {
      sampledBanner.style.display = 'none';
    }
  }

  // Metadata quality panel
  const mqPanel = document.getElementById('metaQualityPanel');
  if (mqPanel) {
    let mq = r.metadata_quality || r.metadataQuality || null;
    if (!mq && r.metadata_quality_json) {
      try { mq = JSON.parse(r.metadata_quality_json); } catch (_) {}
    }
    if (!mq && r.metadataQualityJson) {
      try { mq = JSON.parse(r.metadataQualityJson); } catch (_) {}
    }
    mq = mq || {};
    if (Object.keys(mq).length > 1) {
      const items = [
        mq.missing_src_ip > 0  ? `⚠️ تدفقات بدون source IP: <strong>${mq.missing_src_ip}</strong>` : null,
        mq.ipv6_flows > 0      ? `ℹ️ تدفقات IPv6: <strong>${mq.ipv6_flows}</strong>` : null,
        mq.icmp_like_flows > 0 ? `ℹ️ تدفقات ICMP: <strong>${mq.icmp_like_flows}</strong>` : null,
        mq.multiple_source_flows > 0 ? `ℹ️ تدفقات متعددة المصادر: <strong>${mq.multiple_source_flows}</strong>` : null,
      ].filter(Boolean);
      if (items.length) {
        mqPanel.style.display = '';
        mqPanel.innerHTML = `<div style="font-weight:600;margin-bottom:8px;color:var(--accent)">📊 جودة بيانات الملف</div>` + items.map(i => `<div style="margin:4px 0;font-size:0.92rem">${i}</div>`).join('');
      } else {
        mqPanel.style.display = 'none';
      }
    } else {
      mqPanel.style.display = 'none';
    }
  }

  const body = document.getElementById('resultsBody');
  const types = Object.entries(breakdown).filter(([k]) => k !== 'Benign');
  if (!types.length) {
    body.innerHTML = `<tr><td colspan="4" style="text-align:center;padding:40px;color:var(--muted)">No attacks detected — all flows classified as Benign ✅</td></tr>`;
    return;
  }
  body.innerHTML = types.map(([type, count]) => {
    const sev = severityFor(type);
    return `
      <tr>
        <td><strong>${type}</strong></td>
        <td class="mono">${count}</td>
        <td><span class="badge-sev ${sev.toLowerCase()}">${sev}</span></td>
        <td class="cell-ip">—</td>
      </tr>`;
  }).join('');
}
function severityFor(type) {
  const t = type.toLowerCase();
  if (t.includes('ddos') || t.includes('exploit') || t.includes('bot')) return 'CRITICAL';
  if (t.includes('brute') || t.includes('infiltration') || t.includes('web')) return 'HIGH';
  if (t.includes('scan') || t.includes('recon')) return 'MEDIUM';
  return 'LOW';
}
function setText(id, v) { const el = document.getElementById(id); if (el) el.textContent = v; }

// ===== Reset button =====
resetBtn?.addEventListener('click', () => {
  resultsSec.style.display = 'none';
  progPanel.style.display = 'none';
  fileInput.value = '';
  resetStages();
  clearScanPoll();
  activeScanId = null;
});

// ===== Recent scans table =====
async function loadRecent() {
  const body = document.getElementById('recentBody');
  if (!body) return;
  try {
    const scans = await AisecAPI.listScans();
    if (!scans || !scans.length) {
      body.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--muted)">No scans yet</td></tr>`;
      return;
    }
    body.innerHTML = scans.map(s => `
      <tr>
        <td><i class="fa-regular fa-file-lines" style="color:#22b8cf;margin-right:8px"></i>${s.filename || '(unnamed)'}</td>
        <td>${renderStatusBadge(s.status)}</td>
        <td class="mono">${formatOrDash(s.total_flows)}</td>
        <td><span class="badge-sev ${(s.attack_count > 0 ? 'critical' : 'low')}">${s.attack_count || 0}</span></td>
        <td class="mono">${formatPercent(s.avg_confidence)}</td>
        <td class="muted">${timeAgo(s.created_at)}</td>
      </tr>`).join('');
  } catch (err) {
    body.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--muted)">Failed to load scans: ${err.message}</td></tr>`;
  }
}
function formatOrDash(num) {
  if (num === null || num === undefined) return '—';
  return Number(num).toLocaleString();
}
function formatPercent(value) {
  if (value === null || value === undefined) return '—';
  return `${((value || 0) * 100).toFixed(1)}%`;
}
function timeAgo(iso) {
  if (!iso) return '—';
  const d = (Date.now() - new Date(iso).getTime()) / 1000;
  if (d < 60)    return Math.floor(d) + ' sec ago';
  if (d < 3600)  return Math.floor(d/60) + ' min ago';
  if (d < 86400) return Math.floor(d/3600) + ' hours ago';
  return Math.floor(d/86400) + ' days ago';
}
loadRecent();

// Live updates — keep recent-scans table fresh across tabs/devices
try {
  AisecAPI.connectAlertsWS({
    onMessage: (msg) => {
      if (msg && msg.type === 'scan_complete') loadRecent();
    }
  });
} catch {}

function renderStatusBadge(status) {
  const normalized = (status || 'PROCESSING').toUpperCase();
  const cls = normalized === 'COMPLETED'
    ? 'status-completed'
    : normalized === 'FAILED'
      ? 'status-failed'
      : 'status-processing';
  return `<span class="badge-status ${cls}"><span class="dot"></span>${normalized}</span>`;
}
