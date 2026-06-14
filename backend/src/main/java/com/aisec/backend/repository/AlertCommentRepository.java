package com.aisec.backend.repository;

import com.aisec.backend.entity.AlertComment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AlertCommentRepository extends JpaRepository<AlertComment, Long> {
    List<AlertComment> findByAlertIdOrderByCreatedAtAsc(Long alertId);
    long countByAlertId(Long alertId);
    void deleteByAlertId(Long alertId);
}
