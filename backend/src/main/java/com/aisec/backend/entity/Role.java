package com.aisec.backend.entity;

public enum Role {
    ADMIN,      // system-level superadmin — sees ALL data across ALL organisations
    ORG_ADMIN,  // company/org-level admin — full control but scoped to their organisation only
    ANALYST,    // can view + update alerts
    VIEWER      // read-only
}
