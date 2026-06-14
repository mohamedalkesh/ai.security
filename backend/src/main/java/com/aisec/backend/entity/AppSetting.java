package com.aisec.backend.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Singleton row storing all platform settings as a JSON string.
 * Only one row is ever expected (id = 1).
 */
@Entity
@Table(name = "app_settings")
public class AppSetting {

    @Id
    private Long id = 1L;

    @Lob
    @Column(columnDefinition = "TEXT", nullable = false)
    private String payload = "{}";

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    @Column(length = 64)
    private String updatedBy;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
    public String getUpdatedBy() { return updatedBy; }
    public void setUpdatedBy(String updatedBy) { this.updatedBy = updatedBy; }
}
