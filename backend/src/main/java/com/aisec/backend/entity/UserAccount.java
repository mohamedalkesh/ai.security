package com.aisec.backend.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "users")
public class UserAccount {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 80)
    private String username;

    @Column(unique = true, nullable = false, length = 160)
    private String email;

    @Column(nullable = false, length = 100)
    private String fullName;

    @Column(nullable = false)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Role role = Role.VIEWER;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    private Instant lastLoginAt;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "organization_id")
    private Organization organization;

    public Long getId() { return id; }
    public String getUsername() { return username; }
    public void setUsername(String u) { this.username = u; }
    public String getEmail() { return email; }
    public void setEmail(String e) { this.email = e; }
    public String getFullName() { return fullName; }
    public void setFullName(String n) { this.fullName = n; }
    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String p) { this.passwordHash = p; }
    public Role getRole() { return role; }
    public void setRole(Role r) { this.role = r; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean e) { this.enabled = e; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getLastLoginAt() { return lastLoginAt; }
    public void setLastLoginAt(Instant t) { this.lastLoginAt = t; }
    public Organization getOrganization() { return organization; }
    public void setOrganization(Organization org) { this.organization = org; }
}
