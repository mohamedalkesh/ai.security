package com.aisec.backend.repository;

import com.aisec.backend.entity.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    @Query("SELECT a FROM AuditLog a WHERE (:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId")
    Page<AuditLog> findScoped(@Param("orgId") Long orgId, Pageable pageable);

    @Query("SELECT a FROM AuditLog a WHERE ((:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId) AND a.action = :action")
    Page<AuditLog> findScopedByAction(@Param("orgId") Long orgId, @Param("action") String action, Pageable pageable);

    @Query("SELECT a FROM AuditLog a WHERE ((:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId) AND a.actorUsername = :user")
    Page<AuditLog> findScopedByActor(@Param("orgId") Long orgId, @Param("user") String user, Pageable pageable);
}
