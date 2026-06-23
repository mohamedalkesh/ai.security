/* Webhook management page — list / create / edit / rotate / delete. */
(function () {
  const api = window.AisecAPI;
  if (!api) return;
  if (!api.isAuthenticated()) { window.location.href = "login.html"; return; }
  api.applyRbac && api.applyRbac();

  const $ = (id) => document.getElementById(id);
  const list = $("whList");
  const modalBg = $("whModalBg");

  function openModal(wh) {
    $("whModalTitle").textContent = wh ? "Edit Webhook" : "New Webhook";
    $("whEditId").value = wh ? wh.id : "";
    $("whName").value = wh ? wh.name : "";
    $("whUrl").value  = wh ? wh.url  : "";
    $("whPreset").value = wh ? (wh.preset || "generic") : "generic";
    $("whMinSev").value = wh ? wh.minSeverity : "HIGH";
    $("whEnabled").checked = wh ? wh.enabled : true;
    $("whSecretBox").style.display = "none";
    modalBg.style.display = "flex";
  }
  function closeModal() { modalBg.style.display = "none"; }
  $("whCancelBtn").onclick = closeModal;
  $("newWhBtn").onclick    = () => openModal(null);
  modalBg.onclick = (e) => { if (e.target === modalBg) closeModal(); };

  async function load() {
    list.innerHTML = '<div class="muted" style="padding:20px;text-align:center">Loading…</div>';
    try {
      const items = await api.listWebhooks();
      if (!items.length) {
        list.innerHTML = `
          <div class="wh-card" style="text-align:center;padding:40px">
            <i class="fa-solid fa-bell-slash" style="font-size:32px;color:#4a6080;margin-bottom:12px;display:block"></i>
            <div class="muted">No webhooks configured yet.</div>
            <div class="muted sm" style="margin-top:6px">Click <strong>New Webhook</strong> to push alerts to Slack, Discord, or any HTTPS endpoint.</div>
          </div>`;
        return;
      }
      list.innerHTML = items.map(renderCard).join("");
      bindCardActions(items);
    } catch (e) {
      list.innerHTML = `<div class="wh-card" style="color:#fca5a5">Failed to load: ${e.message}</div>`;
    }
  }

  function renderCard(w) {
    const status = w.enabled
      ? '<span class="wh-status wh-on"><i class="fa-solid fa-circle"></i> Enabled</span>'
      : '<span class="wh-status wh-off"><i class="fa-solid fa-circle"></i> Disabled</span>';
    const lastFail = (w.last_status_code != null && w.last_status_code >= 400)
      ? `<span class="wh-status wh-fail">Last: HTTP ${w.last_status_code}</span>` : "";
    const lastDelivered = w.last_delivered_at
      ? new Date(w.last_delivered_at).toLocaleString()
      : "never";
    return `
      <div class="wh-card" data-id="${w.id}">
        <div class="wh-row">
          <div style="flex:1">
            <div class="wh-name">${escape(w.name)} <small class="muted" style="font-weight:400">· ${w.preset || "generic"}</small></div>
            <div class="wh-url">${escape(w.url)}</div>
            <div class="wh-meta">
              <span>Min severity: <strong>${w.min_severity}</strong></span>
              <span>Last delivered: <strong>${lastDelivered}</strong></span>
              ${w.last_status_code ? `<span>Last status: <strong>${w.last_status_code}</strong></span>` : ""}
            </div>
          </div>
          <div style="display:flex;flex-direction:column;align-items:flex-end;gap:8px">
            ${status}${lastFail}
            <div class="wh-actions">
              <button class="icon-btn wh-edit" title="Edit"><i class="fa-solid fa-pen"></i></button>
              <button class="icon-btn wh-rotate" title="Rotate secret"><i class="fa-solid fa-key"></i></button>
              <button class="icon-btn wh-delete" title="Delete" style="color:#fca5a5"><i class="fa-solid fa-trash"></i></button>
            </div>
          </div>
        </div>
      </div>`;
  }

  function bindCardActions(items) {
    document.querySelectorAll(".wh-card[data-id]").forEach(card => {
      const id = +card.dataset.id;
      const wh = items.find(x => x.id === id);
      card.querySelector(".wh-edit")  .onclick = () => openModal(wh);
      card.querySelector(".wh-delete").onclick = async () => {
        if (!confirm(`Delete webhook "${wh.name}"?`)) return;
        try { await api.deleteWebhook(id); load(); }
        catch (e) { alert("Delete failed: " + e.message); }
      };
      card.querySelector(".wh-rotate").onclick = async () => {
        if (!confirm("Rotate the signing secret? Receivers will need the new value.")) return;
        try {
          const r = await api.rotateWebhookSecret(id);
          showSecret(r.secret);
        } catch (e) { alert("Rotate failed: " + e.message); }
      };
    });
  }

  function showSecret(secret) {
    $("whSecretValue").textContent = secret;
    $("whSecretBox").style.display = "block";
    modalBg.style.display = "flex";
    $("whModalTitle").textContent = "Webhook Secret";
  }

  $("whSaveBtn").onclick = async () => {
    const id = $("whEditId").value;
    const body = {
      name:       $("whName").value.trim(),
      url:        $("whUrl").value.trim(),
      preset:     $("whPreset").value,
      minSeverity:$("whMinSev").value,
      enabled:    $("whEnabled").checked
    };
    if (!body.name || !body.url) { alert("Name and URL are required"); return; }
    if (!/^https?:\/\//.test(body.url)) { alert("URL must start with http:// or https://"); return; }

    try {
      if (id) {
        await api.updateWebhook(+id, body);
        closeModal();
      } else {
        const r = await api.createWebhook(body);
        // r = { config, secret }
        showSecret(r.secret);
      }
      load();
    } catch (e) { alert("Save failed: " + e.message); }
  };

  function escape(s) {
    if (s == null) return "";
    return String(s).replace(/[&<>"']/g, c => ({
      "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"
    }[c]));
  }

  load();
})();
