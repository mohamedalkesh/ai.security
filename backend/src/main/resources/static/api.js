// Shared API client for MADRS frontend
// Talks to the Java Spring Boot backend on http://localhost:8080
(function (global) {
  // Auto-detect host: if page is loaded from 127.0.0.1 use 127.0.0.1 for backend too
  // (avoids CORS edge-cases between localhost / 127.0.0.1 in some browsers).
  const _host = (location.hostname && location.hostname !== "" && location.hostname !== "null")
                ? location.hostname : "127.0.0.1";
  const _isTunnel  = _host.includes("loca.lt") || _host.includes("ngrok") || _host.includes("ngrok-free.app");
  const _isRailway = _host.includes("railway.app");
  const _backendRailway = "https://backend-production-04542.up.railway.app";
  const API_BASE = (global.AISEC_API_BASE && global.AISEC_API_BASE !== "") ? global.AISEC_API_BASE :
                   (_isRailway ? _backendRailway + "/api" :
                   (_isTunnel  ? "https://spotty-elephant-93.loca.lt/api" : "http://" + _host + ":8080/api"));
  const WS_BASE  = (global.AISEC_WS_BASE  && global.AISEC_WS_BASE  !== "") ? global.AISEC_WS_BASE  :
                   (_isRailway ? _backendRailway.replace("https://","wss://") + "/ws" :
                   (_isTunnel  ? "wss://spotty-elephant-93.loca.lt/ws"    : "ws://"   + _host + ":8080/ws"));
  const STORAGE_KEY = "aisec_session";

  // ---------- key-case helper ----------
  // Backend uses Jackson SNAKE_CASE; this lets callers write natural JS camelCase.
  // Recursively rewrites object keys (arrays/primitives untouched).
  function _snakeize(v) {
    if (Array.isArray(v)) return v.map(_snakeize);
    if (v && typeof v === "object" && v.constructor === Object) {
      const out = {};
      for (const k of Object.keys(v)) {
        const sk = k.replace(/([A-Z])/g, "_$1").toLowerCase();
        out[sk] = _snakeize(v[k]);
      }
      return out;
    }
    return v;
  }

  // ---------- session ----------
  function getSession() {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "null"); }
    catch { return null; }
  }
  function setSession(s) { localStorage.setItem(STORAGE_KEY, JSON.stringify(s)); }
  function clearSession() { localStorage.removeItem(STORAGE_KEY); }
  function isAuthenticated() { return !!(getSession() && getSession().token); }
  function logout(redirectTo) {
    clearSession();
    if (redirectTo !== false) window.location.href = redirectTo || "login.html";
  }
  function requireAuth(loginPage) {
    if (!isAuthenticated()) {
      window.location.href = loginPage || "login.html";
      return false;
    }
    return true;
  }

  // ---------- core request ----------
  async function request(path, options = {}) {
    const url = API_BASE + path;
    const session = getSession();
    const headers = { "Accept": "application/json", ...(options.headers || {}) };
    if (session && session.token && !options.skipAuth) {
      headers["Authorization"] = "Bearer " + session.token;
    }
    const opts = { method: options.method || "GET", headers, body: options.body };
    if (opts.body && !(opts.body instanceof FormData) && typeof opts.body !== "string") {
      headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }
    const res = await fetch(url, opts);
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }
    if (res.status === 401) {
      clearSession();
      // Redirect on auth-required pages, but only if not already on the login page
      if (!options.skipAuthRedirect && !location.pathname.endsWith("login.html")) {
        window.location.href = "login.html";
      }
    }
    if (!res.ok) {
      const msg = (data && (data.detail || data.message || data.error)) || ("HTTP " + res.status);
      const err = new Error(msg);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  // ---------- WebSocket ----------
  function connectAlertsWS(handlers) {
    handlers = handlers || {};
    const sess = getSession();
    if (!sess || !sess.token) {
      // Don't attempt unauthenticated WS connections
      handlers.onError && handlers.onError(new Error("No session token"));
      return null;
    }
    const url = WS_BASE + "/alerts?token=" + encodeURIComponent(sess.token);
    const ws = new WebSocket(url);
    ws.onopen    = () => handlers.onOpen  && handlers.onOpen(ws);
    ws.onclose   = (ev) => handlers.onClose && handlers.onClose(ev);
    ws.onerror   = (e) => handlers.onError && handlers.onError(e);
    ws.onmessage = (m) => {
      let payload = m.data;
      try { payload = JSON.parse(m.data); } catch {}
      handlers.onMessage && handlers.onMessage(payload);
    };
    return ws;
  }

  // ---------- Role helpers ----------
  function getRole() {
    const s = getSession();
    return s && s.role ? String(s.role).toUpperCase() : null;
  }
  function isOrgUser() {
    const s = getSession();
    return !!(s && s.organizationId);
  }
  function getOrgId()   { const s = getSession(); return s ? (s.organizationId   ?? null) : null; }
  function getOrgName() { const s = getSession(); return s ? (s.organizationName ?? null) : null; }
  function hasRole(...roles) {
    const r = getRole();
    return !!r && roles.map(x => String(x).toUpperCase()).includes(r);
  }
  /**
   * Checks whether the current user has admin-level access:
   * - ADMIN = system admin (all data)
   * - ORG_ADMIN = org-scoped admin (full control within their org)
   */
  function isAdmin() { return hasRole("ADMIN", "ORG_ADMIN"); }
  /**
   * Hide/disable elements tagged with `data-requires-role` that the current user
   * does not satisfy. Usage in HTML:
   *   <button data-requires-role="ADMIN">Delete</button>           — only system ADMIN
   *   <button data-requires-role="ADMIN,ORG_ADMIN">Edit</button>  — both admin types
   *   <div    data-requires-role="ADMIN,ANALYST">...</div>
   */
  function applyRbac(root) {
    const scope = root || document;
    const role = getRole();
    scope.querySelectorAll("[data-requires-role]").forEach(el => {
      const allowed = (el.getAttribute("data-requires-role") || "")
        .split(",").map(s => s.trim().toUpperCase()).filter(Boolean);
      const ok = role && allowed.includes(role);
      if (!ok) {
        if (el.matches("button, input, select, textarea")) {
          el.setAttribute("disabled", "disabled");
          el.setAttribute("title", "Insufficient role — requires: " + allowed.join(" or "));
          el.style.opacity = "0.45";
          el.style.pointerEvents = "none";
        } else {
          el.style.display = "none";
        }
      }
    });
  }

  // ---------- API surface ----------
  const api = {
    base: API_BASE,
    wsBase: WS_BASE,
    // session
    getSession, setSession, clearSession, isAuthenticated, logout, requireAuth,

    // auth
    login: async (username, password) => {
      const data = await request("/auth/login",
        { method: "POST", body: { username, password }, skipAuth: true, skipAuthRedirect: true });
      setSession({
        token: data.token, username: data.username, role: data.role,
        fullName: data.full_name, expiresAt: Date.now() + (data.expires_in_ms || 0),
        organizationId: data.organizationId ?? null,
        organizationName: data.organizationName ?? null
      });
      return data;
    },
    register: (req) => request("/auth/register",
      { method: "POST", body: req, skipAuth: true, skipAuthRedirect: true }),
    me: () => request("/auth/me"),
    forgotPassword: (email) => request("/auth/forgot-password",
      { method: "POST", body: { email }, skipAuth: true, skipAuthRedirect: true }),
    verifyResetCode: (email, code) => request("/auth/verify-reset-code",
      { method: "POST", body: { email, code }, skipAuth: true, skipAuthRedirect: true }),
    resetPassword: (email, code, newPassword) => request("/auth/reset-password",
      { method: "POST", body: { email, code, new_password: newPassword }, skipAuth: true, skipAuthRedirect: true }),
    sendWelcomeEmail: ({ email, fullName, username, password }) => request("/auth/welcome-email",
      { method: "POST", body: { email, full_name: fullName, username, password } }),

    // platform
    health:     () => request("/health", { skipAuthRedirect: true }),
    modelInfo:  () => request("/model/info"),
    companyRequest: (payload) => request("/company-request", { method: "POST", body: payload, skipAuth: true, skipAuthRedirect: true }),

    // alerts
    listAlerts: (params = {}) => {
      const qs = new URLSearchParams(params).toString();
      return request("/alerts" + (qs ? "?" + qs : ""));
    },
    getAlert:    (id) => request("/alerts/" + id),
    alertStats:  ()   => request("/alerts/stats"),
    alertBreakdown: () => request("/alerts/breakdown"),
    updateAlert: (id, status) => request("/alerts/" + id, { method: "PATCH", body: { status } }),
    /** Multi-field PATCH — pass any subset of {status, assignedToId, mlFeedback}. */
    patchAlert:  (id, patch)  => request("/alerts/" + id, { method: "PATCH", body: _snakeize(patch) }),
    deleteAlert: (id) => request("/alerts/" + id, { method: "DELETE" }),
    bulkUpdateAlerts: (ids, body) =>
        request("/alerts/bulk", { method: "PATCH", body: _snakeize({ ids, ...body }) }),
    autoResolveAlerts: (payload) =>
        request("/alerts/auto-resolve", { method: "POST", body: payload }),
    listAlertComments: (id) => request("/alerts/" + id + "/comments"),
    addAlertComment:   (id, body) =>
        request("/alerts/" + id + "/comments", { method: "POST", body: { body } }),

    // incidents (correlated alerts)
    listIncidents: (params = {}) => {
      const qs = new URLSearchParams(params).toString();
      return request("/incidents" + (qs ? "?" + qs : ""));
    },
    getIncident:    (id) => request("/incidents/" + id),
    updateIncident: (id, status) => request("/incidents/" + id, { method: "PATCH", body: { status } }),

    // audit log (admin-only)
    listAuditLogs: (params = {}) => {
      const qs = new URLSearchParams(params).toString();
      return request("/audit-logs" + (qs ? "?" + qs : ""));
    },

    // webhooks (admin / org_admin)
    listWebhooks:   ()        => request("/webhooks"),
    createWebhook:  (body)    => request("/webhooks", { method: "POST", body }),
    updateWebhook:  (id, body)=> request("/webhooks/" + id, { method: "PUT",  body }),
    deleteWebhook:  (id)      => request("/webhooks/" + id, { method: "DELETE" }),
    rotateWebhookSecret: (id) => request("/webhooks/" + id + "/rotate-secret", { method: "POST" }),

    // analytics (read-only, all roles)
    analyticsSummary:    (days = 14) => request("/analytics/summary?days=" + days),
    analyticsMttr:       ()          => request("/analytics/mttr"),
    analyticsTrend:      (days = 14) => request("/analytics/trend?days=" + days),
    analyticsTopAttackers: (limit = 10, days = 7) =>
      request("/analytics/top-attackers?limit=" + limit + "&days=" + days),

    // scans / predictions
    predictFlow: (features) => request("/predict/flow", { method: "POST", body: { features } }),
    predictPcap: (file) => {
      const fd = new FormData();
      fd.append("file", file);
      return request("/predict/pcap", { method: "POST", body: fd });
    },
    getScan: (id) => request("/scans/" + id),
    listScans: () => request("/scans"),

    // users (admin/analyst)
    listUsers:  ()   => request("/users"),
    getUser:    (id) => request("/users/" + id),
    createUser: (req) => request("/users", { method: "POST", body: req }),
    changeRole: (id, role) =>
      request("/users/" + id + "/role?role=" + encodeURIComponent(role), { method: "PUT" }),
    deleteUser: (id) => request("/users/" + id, { method: "DELETE" }),

    // organisations (admin-only)
    listOrganizations: () => request("/organizations"),

    // reports
    reportSummary: () => request("/reports/summary"),
    exportReportUrl: (fmt) => API_BASE + "/reports/export." + fmt,
    downloadReport: async (fmt) => {
      const sess = getSession();
      const token = sess && sess.token;
      const res = await fetch(API_BASE + "/reports/export." + fmt, {
        headers: token ? { Authorization: "Bearer " + token } : {}
      });
      if (!res.ok) { const err = new Error("HTTP " + res.status); err.status = res.status; throw err; }
      const blob = await res.blob();
      // Extract filename from Content-Disposition
      let name = "report." + fmt;
      const disp = res.headers.get("Content-Disposition") || "";
      const m = disp.match(/filename="?([^";]+)"?/i);
      if (m) name = m[1];
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      return { name, size: blob.size };
    },
    downloadAnalysisReport: async (alertId) => {
      if (!alertId) throw new Error("Missing alert id");
      const sess = getSession();
      const token = sess && sess.token;
      const res = await fetch(API_BASE + "/reports/analysis/" + alertId + ".pdf", {
        headers: token ? { Authorization: "Bearer " + token } : {}
      });
      if (!res.ok) { const err = new Error("HTTP " + res.status); err.status = res.status; throw err; }
      const blob = await res.blob();
      let name = `analysis-${alertId}.pdf`;
      const disp = res.headers.get("Content-Disposition") || "";
      const m = disp.match(/filename="?([^";]+)"?/i);
      if (m) name = m[1];
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      return { name, size: blob.size };
    },
    downloadMitreReport: async (alertId) => {
      if (!alertId) throw new Error("Missing alert id");
      const sess = getSession();
      const token = sess && sess.token;
      const res = await fetch(API_BASE + "/reports/mitre/" + alertId + ".pdf", {
        headers: token ? { Authorization: "Bearer " + token } : {}
      });
      if (!res.ok) { const err = new Error("HTTP " + res.status); err.status = res.status; throw err; }
      const blob = await res.blob();
      let name = `mitre-${alertId}.pdf`;
      const disp = res.headers.get("Content-Disposition") || "";
      const m = disp.match(/filename="?([^";]+)"?/i);
      if (m) name = m[1];
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      return { name, size: blob.size };
    },
    downloadResponsePlan: async (alertId) => {
      if (!alertId) throw new Error("Missing alert id");
      const sess = getSession();
      const token = sess && sess.token;
      const res = await fetch(API_BASE + "/reports/response/" + alertId + ".pdf", {
        headers: token ? { Authorization: "Bearer " + token } : {}
      });
      if (!res.ok) { const err = new Error("HTTP " + res.status); err.status = res.status; throw err; }
      const blob = await res.blob();
      let name = `response-plan-${alertId}.pdf`;
      const disp = res.headers.get("Content-Disposition") || "";
      const m = disp.match(/filename="?([^";]+)"?/i);
      if (m) name = m[1];
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      return { name, size: blob.size };
    },

    // system metrics (live)
    metrics: () => request("/metrics"),

    // live network monitor
    monitorInterfaces: () => request("/monitor/interfaces"),
    // iface can be a single string or an array of interface names
    monitorStart: (iface) => {
      const body = Array.isArray(iface)
        ? { interfaces: iface }
        : { interface: iface };
      return request("/monitor/start", { method: "POST", body });
    },
    monitorStop: () => request("/monitor/stop", { method: "POST" }),
    monitorStatus: () => request("/monitor/status"),
    monitorSetAutostart: (iface) => {
      const body = Array.isArray(iface)
        ? { interfaces: iface }
        : { interface: iface };
      return request("/monitor/autostart", { method: "POST", body });
    },

    // network-wide ARP isolation
    monitorIsolate: (ip, reason) =>
      request("/monitor/isolate", { method: "POST", body: { ip, reason: reason || "" } }),
    monitorRelease: (ip) =>
      request("/monitor/isolate/" + encodeURIComponent(ip), { method: "DELETE" }),
    monitorListIsolated: () => request("/monitor/isolated"),

    // firewall blocklist
    listBlockedIps: (params = {}) => {
      const qs = new URLSearchParams(params).toString();
      return request("/firewall/blocklist" + (qs ? "?" + qs : ""));
    },
    blockIp: (payload) => request("/firewall/blocklist",
      { method: "POST", body: _snakeize(payload) }),
    unblockIp: (id) => request("/firewall/blocklist/" + id, { method: "DELETE" }),
    checkBlockedIp: (ip) => request("/firewall/blocklist/check?ip=" + encodeURIComponent(ip)),
    firewallStats: () => request("/firewall/stats"),
    backfillAutoBlocks: () => request("/firewall/blocklist/backfill", { method: "POST" }),

    // threat-intel (AbuseIPDB-backed; falls back to deterministic mock in dev)
    lookupReputation:  (ip) => request("/threat-intel/" + encodeURIComponent(ip)),
    refreshReputation: (ip) => request("/threat-intel/" + encodeURIComponent(ip) + "/refresh",
      { method: "POST" }),

    // platform settings (persisted server-side)
    getSettings:    () => request("/settings"),
    updateSettings: (payload) => request("/settings", { method: "PUT", body: payload }),
    resetSettings:  () => request("/settings/reset", { method: "POST" }),

    // websocket
    connectAlertsWS,

    // rbac
    getRole, hasRole, applyRbac, isAdmin,
    // org helpers
    isOrgUser, getOrgId, getOrgName,
    assets: {
      logo: 'assets/madrs-badge.svg',
      icon: 'assets/madrs-icon.svg'
    }
  };

  global.AisecAPI = api;

  // ---------- Page-level access control ----------
  // Maps page filename → minimum roles allowed (others get redirected to dashboard)
  const PAGE_ACCESS = {
    'scan.html':         ['ADMIN', 'ORG_ADMIN', 'ANALYST'],
    'monitoring.html':   ['ADMIN', 'ORG_ADMIN', 'ANALYST'],
    'users.html':        ['ADMIN', 'ORG_ADMIN'],
    'settings.html':     ['ADMIN'],
    'reports.html':      ['ADMIN', 'ORG_ADMIN', 'ANALYST'],
    'alerts.html':       ['ADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'],
    'dashboard.html':    ['ADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'],
    'notifications.html':['ADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'],
    'contact.html':      ['ADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'],
    'incidents.html':    ['ADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'],
    'audit.html':        ['ADMIN', 'ORG_ADMIN'],
    'webhooks.html':     ['ADMIN', 'ORG_ADMIN'],
    'analytics.html':    ['ADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'],
    'firewall.html':     ['ADMIN', 'ORG_ADMIN', 'ANALYST']
  };

  // Sidebar links to hide per role
  const SIDEBAR_ACCESS = {
    'scan.html':       ['ADMIN', 'ORG_ADMIN', 'ANALYST'],
    'monitoring.html': ['ADMIN', 'ORG_ADMIN', 'ANALYST'],
    'users.html':      ['ADMIN', 'ORG_ADMIN'],
    'settings.html':   ['ADMIN'],
    'reports.html':    ['ADMIN', 'ORG_ADMIN', 'ANALYST'],
    'audit.html':      ['ADMIN', 'ORG_ADMIN'],
    'webhooks.html':   ['ADMIN', 'ORG_ADMIN'],
    'analytics.html':  ['ADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'],
    'firewall.html':   ['ADMIN', 'ORG_ADMIN', 'ANALYST']
  };

  function enforcePageAccess() {
    if (!api.isAuthenticated()) return;
    const page = location.pathname.split('/').pop() || 'dashboard.html';
    const role = getRole();
    const allowed = PAGE_ACCESS[page];
    if (allowed && !allowed.includes(role)) {
      window.location.replace('dashboard.html');
    }
  }

  function enforceSidebarAccess() {
    const role = getRole();
    if (!role) return;
    Object.entries(SIDEBAR_ACCESS).forEach(([page, roles]) => {
      if (!roles.includes(role)) {
        document.querySelectorAll(`.side-link[href="${page}"]`).forEach(el => {
          el.style.display = 'none';
        });
      }
    });
  }

  // ---------- global wiring (every page) ----------
  function wireGlobals() {
    // Enforce page access based on role
    try { enforcePageAccess(); } catch {}

    // Hide sidebar links the user can't access
    try { enforceSidebarAccess(); } catch {}

    // Ensure any cached legacy branding is updated to MADRS
    try {
      const replaceLegacy = (selector, replacement) => {
        document.querySelectorAll(selector).forEach(el => {
          const txt = (el.textContent || "").trim();
          if (/ai\s*security/i.test(txt) || /ai\s*security\s*platform/i.test(txt)) {
            el.textContent = replacement;
          }
        });
      };
      replaceLegacy('.side-title', 'MADRS');
      replaceLegacy('.brand-name', 'MADRS');
      document.querySelectorAll('.brand-sub, .side-sub').forEach(el => {
        const txt = (el.textContent || "").trim();
        if (/ai\s*security/i.test(txt)) {
          el.textContent = 'MITRE ATT&CK Detection & Response';
        }
      });

      const MADRS_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" fill="none" style="width:78%;height:78%;filter:drop-shadow(0 0 7px rgba(46,232,255,.5))">
        <defs>
          <linearGradient id="mA" x1="20" y1="10" x2="80" y2="90" gradientUnits="userSpaceOnUse">
            <stop offset="0" stop-color="#2EE8FF"/><stop offset="1" stop-color="#1560FF"/>
          </linearGradient>
          <radialGradient id="mB" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="#0A1E35"/><stop offset="100%" stop-color="#020C1A"/>
          </radialGradient>
        </defs>
        <polygon points="50,4 91,27 91,73 50,96 9,73 9,27" fill="url(#mB)" stroke="url(#mA)" stroke-width="2.2"/>
        <polygon points="50,16 80,33 80,67 50,84 20,67 20,33" fill="none" stroke="#22d4ff" stroke-width="1.2" stroke-opacity="0.5"/>
        <circle cx="50" cy="50" r="24" stroke="#22d4ff" stroke-width="1" stroke-dasharray="6 5" stroke-opacity="0.4"/>
        <circle cx="50" cy="50" r="15" stroke="#22d4ff" stroke-width="1" stroke-opacity="0.65"/>
        <path d="M28 50 Q50 30 72 50 Q50 70 28 50Z" stroke="#2EE8FF" stroke-width="2" fill="#071624"/>
        <circle cx="50" cy="50" r="10" fill="#0d2640" stroke="#2EE8FF" stroke-width="1.8"/>
        <circle cx="50" cy="50" r="5" fill="#2EE8FF"/>
        <circle cx="50" cy="50" r="2.2" fill="#020C1A"/>
        <circle cx="68" cy="43" r="2.8" fill="#FFB347"/>
        <circle cx="36" cy="58" r="2.8" fill="#FF4D6D"/>
        <line x1="50" y1="18" x2="50" y2="12" stroke="#2EE8FF" stroke-width="1.4" stroke-linecap="round" stroke-opacity="0.7"/>
        <line x1="50" y1="88" x2="50" y2="82" stroke="#2EE8FF" stroke-width="1.4" stroke-linecap="round" stroke-opacity="0.7"/>
        <line x1="12" y1="50" x2="18" y2="50" stroke="#2EE8FF" stroke-width="1.4" stroke-linecap="round" stroke-opacity="0.7"/>
        <line x1="88" y1="50" x2="82" y2="50" stroke="#2EE8FF" stroke-width="1.4" stroke-linecap="round" stroke-opacity="0.7"/>
      </svg>`;
      document.querySelectorAll('.brand-logo').forEach(el => {
        if (el.classList.contains('brand-logo--madrs')) return;
        el.classList.add('brand-logo--madrs');
        el.querySelectorAll('i, img').forEach(node => node.remove());
        el.innerHTML = MADRS_SVG;
      });
    } catch {}

    // Apply role-based UI restrictions (data-requires-role)
    try { applyRbac(); } catch {}

    // Show org name badge for ORG_ADMIN users in the sidebar
    try {
      const orgName = getOrgName();
      const role    = getRole();
      if (orgName && role === 'ORG_ADMIN') {
        const existing = document.getElementById('_orgBadge');
        if (!existing) {
          const badge = document.createElement('div');
          badge.id = '_orgBadge';
          badge.style.cssText = [
            'margin:10px 12px 0',
            'padding:6px 12px',
            'background:rgba(34,184,207,.12)',
            'border:1px solid rgba(34,184,207,.3)',
            'border-radius:8px',
            'font-size:11px',
            'color:#22b8cf',
            'font-weight:600',
            'letter-spacing:.4px',
            'text-transform:uppercase',
            'white-space:nowrap',
            'overflow:hidden',
            'text-overflow:ellipsis'
          ].join(';');
          badge.title = 'Organisation: ' + orgName;
          badge.textContent = '\uD83C\uDFE2 ' + orgName;
          const sidebar = document.querySelector('.sidebar, nav, aside');
          if (sidebar) sidebar.prepend(badge);
        }
      }
    } catch {}

    // Logout link
    document.querySelectorAll('.side-logout').forEach(el => {
      if (el.dataset._wired) return;
      el.dataset._wired = '1';
      el.addEventListener('click', (e) => {
        e.preventDefault();
        api.logout();
      });
    });

    // Live "Alerts" sidebar badge — show count of ACTIVE alerts (or hide if 0)
    if (api.isAuthenticated()) {
      const updateBadge = async () => {
        try {
          const stats = await api.alertStats();
          const n = stats.active || 0;
          document.querySelectorAll('a.side-link[href="alerts.html"]').forEach(link => {
            let badge = link.querySelector('.side-badge');
            if (!badge) {
              badge = document.createElement('span');
              badge.className = 'side-badge';
              link.appendChild(badge);
            }
            if (n > 0) {
              badge.textContent = n;
              badge.style.display = '';
            } else {
              badge.style.display = 'none';
            }
          });
        } catch { /* ignore (e.g., not logged in) */ }
      };
      updateBadge();
      setInterval(updateBadge, 30000);

      // Live: refresh sidebar badge on alert/scan events (every page gets this)
      try {
        let bt = null;
        const debounced = () => { clearTimeout(bt); bt = setTimeout(updateBadge, 400); };
        connectAlertsWS({
          onMessage: (msg) => {
            if (!msg) return;
            if (msg.type === 'alert' || msg.type === 'scan_complete') debounced();
          }
        });
      } catch {}
    }
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wireGlobals);
  } else {
    wireGlobals();
  }
})(window);
