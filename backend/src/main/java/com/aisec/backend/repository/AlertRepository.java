package com.aisec.backend.repository;

import com.aisec.backend.entity.Alert;
import com.aisec.backend.entity.AlertStatus;
import com.aisec.backend.entity.Severity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public interface AlertRepository extends JpaRepository<Alert, Long> {
    Page<Alert> findBySeverity(Severity severity, Pageable pageable);
    Page<Alert> findByStatus(AlertStatus status, Pageable pageable);
    long countByStatus(AlertStatus status);
    long countBySeverity(Severity severity);
    long countByCreatedAtAfter(Instant since);

    @Query("select a.attackType as type, count(a) as count from Alert a group by a.attackType")
    List<Map<String, Object>> countByAttackType();

    List<Alert> findTop30ByOrderByCreatedAtDesc();

    /* ===== Unified org-scoped queries =====
     * Treat null orgId as 'system tenant' (organization IS NULL).
     * Non-null orgId filters strictly by that organisation.
     * Each tenant — including the system owner — sees ONLY their own data.
     */
    @Query("""
            SELECT a FROM Alert a
            WHERE ((:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId)
              AND a.status IN (com.aisec.backend.entity.AlertStatus.NEW, com.aisec.backend.entity.AlertStatus.INVESTIGATING)
            ORDER BY CASE a.severity
                WHEN com.aisec.backend.entity.Severity.CRITICAL THEN 5
                WHEN com.aisec.backend.entity.Severity.HIGH THEN 4
                WHEN com.aisec.backend.entity.Severity.MEDIUM THEN 3
                WHEN com.aisec.backend.entity.Severity.LOW THEN 2
                ELSE 1
            END DESC, a.createdAt DESC
            """)
    Page<Alert> findScoped(@Param("orgId") Long orgId, Pageable pageable);

    @Query("""
            SELECT a FROM Alert a
            WHERE ((:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId)
              AND a.status IN (com.aisec.backend.entity.AlertStatus.NEW, com.aisec.backend.entity.AlertStatus.INVESTIGATING)
              AND a.severity = :severity
            ORDER BY a.createdAt DESC
            """)
    Page<Alert> findScopedBySeverity(@Param("orgId") Long orgId, @Param("severity") Severity severity, Pageable pageable);

    @Query("""
            SELECT a FROM Alert a
            WHERE ((:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId)
              AND a.status = :status
            ORDER BY CASE a.severity
                WHEN com.aisec.backend.entity.Severity.CRITICAL THEN 5
                WHEN com.aisec.backend.entity.Severity.HIGH THEN 4
                WHEN com.aisec.backend.entity.Severity.MEDIUM THEN 3
                WHEN com.aisec.backend.entity.Severity.LOW THEN 2
                ELSE 1
            END DESC, a.createdAt DESC
            """)
    Page<Alert> findScopedByStatus(@Param("orgId") Long orgId, @Param("status") AlertStatus status, Pageable pageable);

    @Query("SELECT COUNT(a) FROM Alert a WHERE (:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId")
    long countScoped(@Param("orgId") Long orgId);

    @Query("SELECT COUNT(a) FROM Alert a WHERE ((:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId) AND a.status = :status")
    long countScopedByStatus(@Param("orgId") Long orgId, @Param("status") AlertStatus status);

    @Query("SELECT COUNT(a) FROM Alert a WHERE ((:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId) AND a.severity = :severity")
    long countScopedBySeverity(@Param("orgId") Long orgId, @Param("severity") Severity severity);

    @Query("SELECT COUNT(a) FROM Alert a WHERE ((:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId) AND a.createdAt > :since")
    long countScopedSince(@Param("orgId") Long orgId, @Param("since") Instant since);

    @Query("SELECT a.attackType AS type, COUNT(a) AS count FROM Alert a WHERE (:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId GROUP BY a.attackType")
    List<Map<String, Object>> countByAttackTypeScoped(@Param("orgId") Long orgId);

    @Query("SELECT a FROM Alert a WHERE (:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId ORDER BY a.createdAt DESC")
    List<Alert> findAllScopedOrdered(@Param("orgId") Long orgId);

    @Query("""
            SELECT a FROM Alert a
            WHERE ((:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId)
              AND a.status IN :statuses
              AND a.severity <= :maxSeverity
              AND (:minConfidence IS NULL OR a.confidence IS NULL OR a.confidence >= :minConfidence)
            ORDER BY a.createdAt ASC
            """)
    Page<Alert> findEligibleForAutoResolve(@Param("orgId") Long orgId,
                                           @Param("statuses") List<AlertStatus> statuses,
                                           @Param("maxSeverity") Severity maxSeverity,
                                           @Param("minConfidence") Double minConfidence,
                                           Pageable pageable);

    /* ===== Analytics queries ===== */

    /** Mean time-to-resolve in seconds (NULL when no resolved alerts). */
    @Query(value = "SELECT EXTRACT(EPOCH FROM AVG(resolved_at - created_at)) " +
                   "FROM alerts WHERE resolved_at IS NOT NULL AND " +
                   "((:orgId IS NULL AND organization_id IS NULL) OR organization_id = :orgId)",
            nativeQuery = true)
    Double mttrSecondsScoped(@Param("orgId") Long orgId);

    /** Daily alert counts since {@code since}. Returns rows of (day, count). */
    @Query(value = "SELECT DATE(created_at) AS day, COUNT(*) AS count " +
                   "FROM alerts WHERE created_at >= :since AND " +
                   "((:orgId IS NULL AND organization_id IS NULL) OR organization_id = :orgId) " +
                   "GROUP BY DATE(created_at) ORDER BY day",
            nativeQuery = true)
    List<Map<String, Object>> dailyCountsScoped(@Param("orgId") Long orgId,
                                                 @Param("since") Instant since);

    /** Top-N attacking source IPs since {@code since}. */
    @Query(value = "SELECT source_ip AS ip, COUNT(*) AS count " +
                   "FROM alerts WHERE source_ip IS NOT NULL AND created_at >= :since AND " +
                   "((:orgId IS NULL AND organization_id IS NULL) OR organization_id = :orgId) " +
                   "GROUP BY source_ip ORDER BY count DESC LIMIT :limit",
            nativeQuery = true)
    List<Map<String, Object>> topAttackersScoped(@Param("orgId") Long orgId,
                                                  @Param("since") Instant since,
                                                  @Param("limit") int limit);

    /** Daily counts grouped by severity for stacked-line charts. */
    @Query(value = "SELECT DATE(created_at) AS day, severity, COUNT(*) AS count " +
                   "FROM alerts WHERE created_at >= :since AND " +
                   "((:orgId IS NULL AND organization_id IS NULL) OR organization_id = :orgId) " +
                   "GROUP BY DATE(created_at), severity ORDER BY day",
            nativeQuery = true)
    List<Map<String, Object>> severityTrendScoped(@Param("orgId") Long orgId,
                                                   @Param("since") Instant since);

    /** All currently-open alerts matching a given source IP, scoped to one tenant. */
    @Query("SELECT a FROM Alert a WHERE a.sourceIp = :ip AND a.status IN :open AND " +
           "((:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId)")
    List<Alert> findOpenBySourceIp(@Param("ip") String ip,
                                    @Param("orgId") Long orgId,
                                    @Param("open") List<AlertStatus> open);

    @Query("SELECT a FROM Alert a WHERE a.sourceIp = :ip AND a.attackType = :attackType AND a.status IN :open AND " +
           "((:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId)")
    List<Alert> findOpenBySourceIpAndAttackType(@Param("ip") String ip,
                                                 @Param("attackType") String attackType,
                                                 @Param("orgId") Long orgId,
                                                 @Param("open") List<AlertStatus> open);

    /** Open alerts whose severity is in the given set — used for backfilling the auto-block rule retroactively. */
    @Query("SELECT a FROM Alert a WHERE a.severity IN :sev AND a.status IN :open AND " +
           "((:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId) " +
           "ORDER BY a.createdAt DESC")
    List<Alert> findOpenBySeverities(@Param("orgId") Long orgId,
                                      @Param("sev") List<com.aisec.backend.entity.Severity> sev,
                                      @Param("open") List<AlertStatus> open);

    /** Count of feedback-labelled alerts in the window — used for retrain triggers. */
    @Query("SELECT COUNT(a) FROM Alert a WHERE a.mlFeedback IS NOT NULL " +
           "AND a.createdAt > :since AND " +
           "((:orgId IS NULL AND a.organization IS NULL) OR a.organization.id = :orgId)")
    long countFeedbackScopedSince(@Param("orgId") Long orgId, @Param("since") Instant since);
}
