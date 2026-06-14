package com.aisec.backend.dto.alert;

import com.aisec.backend.entity.AlertComment;

import java.time.Instant;

public record AlertCommentDto(
        Long id,
        Long alertId,
        String authorUsername,
        String authorRole,
        String body,
        Instant createdAt
) {
    public static AlertCommentDto from(AlertComment c) {
        var author = c.getAuthor();
        return new AlertCommentDto(
                c.getId(),
                c.getAlert() != null ? c.getAlert().getId() : null,
                author != null ? author.getUsername() : "system",
                author != null && author.getRole() != null ? author.getRole().name() : null,
                c.getBody(),
                c.getCreatedAt()
        );
    }
}
