// Firewall blocklist UI — list, add, remove, and live-search blocked IPs.
(() => {
  if (!window.AisecAPI) return;
  if (!AisecAPI.requireAuth?.()) return;

  const wrap         = document.getElementById('fwListWrap');
  const searchEl     = document.getElementById('fwSearch');
  const newBtn       = document.getElementById('fwNewBtn');
  const modal        = document.getElementById('fwModalBg');
  const ipEl         = document.getElementById('fwIp');
  const reasonEl     = document.getElementById('fwReason');
  const expiresEl    = document.getElementById('fwExpires');
  const saveBtn      = document.getElementById('fwSaveBtn');
  const cancelBtn    = document.getElementById('fwCancelBtn');
  const activeStat   = document.getElementById('fwActiveCount');
  const manualStat   = document.getElementById('fwManualCount');
  const autoStat     = document.getElementById('fwAutoCount');
  const toast        = document.getElementById('toast');

  let entries = [];
  let searchTimer = null;

  /* ---------- helpers ---------- */
  function showToast(msg) {
    toast.querySelector('span').textContent = msg;
    toast.classList.add('show');
    clearTimeout(showToast._t);
    showToast._t = setTimeout(() => toast.classList.remove('show'), 1800);
  }

  function fmtTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleString();
  }

  function escapeHtml(s) {
    return String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // Render the reputation badge for a row. Scores 75+ are red ("malicious"),
  // 25-74 amber ("suspicious"), <25 green. Missing reputation surfaces a
  // small "Check" link that the user can click to query on-demand.
  function repBadge(rep) {
    if (!rep) return '<span class="rep-badge rep-unknown" data-action="check-rep" title="Click to query threat intel">Check</span>';
    const s = Number(rep.abuse_score || 0);
    const cls = s >= 75 ? 'rep-bad' : s >= 25 ? 'rep-warn' : 'rep-good';
    const flag = rep.country_code ? `<span class="rep-cc">${escapeHtml(rep.country_code)}</span> ` : '';
    const stale = rep.stale ? ' <span class="rep-stale" title="Cached value past TTL">↻</span>' : '';
    const title = [
      `Score: ${s}/100`,
      rep.country ? 'Country: ' + rep.country : null,
      rep.isp ? 'ISP: ' + rep.isp : null,
      rep.total_reports ? 'Reports: ' + rep.total_reports : null,
      rep.provider ? 'via ' + rep.provider : null,
    ].filter(Boolean).join(' • ');
    return `<span class="rep-badge ${cls}" title="${escapeHtml(title)}">${flag}${s}${stale}</span>`;
  }

  /* ---------- rendering ---------- */
  function render(rows) {
    if (!rows || rows.length === 0) {
      wrap.innerHTML = `
        <div class="fw-empty">
          <div><i class="fa-regular fa-circle-check"></i></div>
          <div>No blocked IPs.</div>
          <div style="margin-top:6px;font-size:12px">Click <strong>Block IP</strong> above to add the first entry.</div>
        </div>`;
      return;
    }

    const body = rows.map(r => `
      <tr data-id="${r.id}" data-ip="${escapeHtml(r.ip)}">
        <td class="ip">${escapeHtml(r.ip)}</td>
        <td class="rep-cell">${repBadge(r.reputation)}</td>
        <td><span class="src-pill src-${escapeHtml(r.source || 'MANUAL')}">${escapeHtml(r.source || 'MANUAL')}</span></td>
        <td class="reason" title="${escapeHtml(r.reason || '')}">${escapeHtml(r.reason || '—')}</td>
        <td class="actor">${escapeHtml(r.created_by || '—')}</td>
        <td class="when">${fmtTime(r.created_at)}</td>
        <td class="when">${r.expires_at ? fmtTime(r.expires_at) : '<span style="color:#475569">never</span>'}</td>
        <td><button class="fw-btn-del" data-action="unblock"><i class="fa-solid fa-trash"></i> Unblock</button></td>
      </tr>`).join('');

    wrap.innerHTML = `
      <table class="fw-table">
        <thead><tr>
          <th>IP / CIDR</th><th>Reputation</th><th>Source</th><th>Reason</th><th>Actor</th>
          <th>Blocked At</th><th>Expires</th><th></th>
        </tr></thead>
        <tbody>${body}</tbody>
      </table>`;

    // Wire up unblock buttons
    wrap.querySelectorAll('button[data-action=unblock]').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const tr = e.target.closest('tr');
        const id = parseInt(tr.dataset.id);
        const ip = tr.querySelector('.ip').textContent;
        if (!confirm(`Unblock ${ip}?`)) return;
        try {
          await AisecAPI.unblockIp(id);
          showToast('✓ ' + ip + ' unblocked');
          await load();
        } catch (err) {
          showToast('Unblock failed: ' + (err.message || 'unknown'));
        }
      });
    });

    // On-demand reputation lookup for rows missing a cached verdict.
    wrap.querySelectorAll('[data-action=check-rep]').forEach(el => {
      el.addEventListener('click', async (e) => {
        e.stopPropagation();
        const tr = e.target.closest('tr');
        const cell = tr.querySelector('.rep-cell');
        const ip = tr.dataset.ip;
        cell.innerHTML = '<span class="rep-badge rep-unknown">…</span>';
        try {
          const rep = await AisecAPI.lookupReputation(ip);
          cell.innerHTML = repBadge(rep || null);
          if (!rep) showToast('No reputation data for ' + ip);
        } catch (err) {
          cell.innerHTML = repBadge(null);
          showToast('Lookup failed: ' + (err.message || 'unknown'));
        }
      });
    });
  }

  function updateStats(rows) {
    activeStat.textContent = rows.filter(r => r.active).length;
    manualStat.textContent = rows.filter(r => r.source === 'MANUAL').length;
    autoStat.textContent   = rows.filter(r => r.source !== 'MANUAL').length;
  }

  /* ---------- data ---------- */
  async function load(q = '') {
    try {
      const params = q ? { q, size: 200 } : { size: 200 };
      const page = await AisecAPI.listBlockedIps(params);
      entries = page.content || page.items || [];
      render(entries);
      updateStats(entries);
    } catch (err) {
      wrap.innerHTML = `<div class="fw-empty" style="color:#fca5a5">Failed to load: ${escapeHtml(err.message || '')}</div>`;
    }
  }

  /* ---------- modal ---------- */
  function openModal() {
    ipEl.value = '';
    reasonEl.value = '';
    expiresEl.value = '';
    modal.classList.add('show');
    setTimeout(() => ipEl.focus(), 50);
  }
  function closeModal() { modal.classList.remove('show'); }

  newBtn.addEventListener('click', openModal);

  // "Apply AI Rule" — retroactively block every open HIGH/CRITICAL alert.
  // Useful right after the feature is enabled, when the DB still holds
  // severe alerts whose source IPs predate the auto-block hook.
  document.getElementById('fwBackfillBtn')?.addEventListener('click', async (e) => {
    if (!confirm('Apply AI auto-block rule to all open HIGH/CRITICAL alerts?\n\n' +
                 'This will add a firewall entry for every severe alert whose source IP isn\'t already blocked.')) return;
    const btn = e.currentTarget;
    btn.disabled = true;
    const orig = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Applying…';
    try {
      const res = await AisecAPI.backfillAutoBlocks();
      showToast('✓ Auto-block applied: ' + (res.created || 0) + ' new entr' + ((res.created === 1) ? 'y' : 'ies'));
      await load(searchEl.value.trim());
    } catch (err) {
      showToast('Apply failed: ' + (err.message || 'unknown'));
    } finally {
      btn.disabled = false;
      btn.innerHTML = orig;
    }
  });
  cancelBtn.addEventListener('click', closeModal);
  modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.classList.contains('show')) closeModal();
  });

  saveBtn.addEventListener('click', async () => {
    const ip = ipEl.value.trim();
    if (!ip) { showToast('IP is required'); return; }
    saveBtn.disabled = true;
    try {
      const payload = { ip, reason: reasonEl.value.trim() || null };
      const exp = expiresEl.value.trim();
      if (exp) payload.expiresAt = exp;
      const res = await AisecAPI.blockIp(payload);
      const ra = res.resolved_alerts || 0;
      const ri = res.resolved_incidents || 0;
      let msg = '✓ ' + ip + ' blocked';
      if (ra || ri) msg += ` — resolved ${ra} alert${ra === 1 ? '' : 's'}`
                         + (ri ? ` & ${ri} incident${ri === 1 ? '' : 's'}` : '');
      showToast(msg);
      closeModal();
      await load(searchEl.value.trim());
    } catch (err) {
      showToast('Block failed: ' + (err.message || 'unknown'));
    } finally {
      saveBtn.disabled = false;
    }
  });

  /* ---------- search ---------- */
  searchEl.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => load(searchEl.value.trim()), 200);
  });

  /* ---------- boot ---------- */
  load();
})();
