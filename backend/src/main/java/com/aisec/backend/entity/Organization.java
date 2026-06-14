package com.aisec.backend.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "organizations")
public class Organization {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 200)
    private String name;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public Long getId() { return id; }
    public String getName() { return name; }
    public void setName(String n) { this.name = n; }
    public Instant getCreatedAt() { return createdAt; }
}
