package com.aisec.backend.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

public class OrgUserDetails extends User {

    private final Long organizationId;

    public OrgUserDetails(String username, String password,
                          Collection<? extends GrantedAuthority> authorities,
                          boolean enabled, Long organizationId) {
        super(username, password, enabled, true, true, true, authorities);
        this.organizationId = organizationId;
    }

    public Long getOrganizationId() { return organizationId; }
}
