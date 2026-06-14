package com.aisec.backend.entity;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "alert_comments", indexes = {
        @Index(name = "idx_alert_comments_alert", columnList = "alert_id"),
        @Index(name = "idx_alert_comments_created", columnList = "createdAt")
})
public class AlertComment {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "alert_id", nullable = false)
    private Alert alert;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "author_id")
    private UserAccount author;

    @Column(nullable = false, length = 4000)
    private String body;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public Long getId() { return id; }
    public Alert getAlert() { return alert; }
    public void setAlert(Alert a) { this.alert = a; }
    public UserAccount getAuthor() { return author; }
    public void setAuthor(UserAccount u) { this.author = u; }
    public String getBody() { return body; }
    public void setBody(String b) { this.body = b; }
    public Instant getCreatedAt() { return createdAt; }
}
