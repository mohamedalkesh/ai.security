package com.aisec.backend.repository;

import com.aisec.backend.entity.MlTrainingRecord;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface MlTrainingRecordRepository extends JpaRepository<MlTrainingRecord, Long> {

    // attackTypePattern must be pre-built in Java as "%value%" (lowercase) to avoid
    // PostgreSQL type-inference errors when applying lower() to a bare ? parameter.
    @Query("""
        SELECT r FROM MlTrainingRecord r
        WHERE ((:orgId IS NULL AND r.organization IS NULL) OR r.organization.id = :orgId)
          AND (:label IS NULL OR r.trueLabel = :label)
          AND (:attackTypePattern IS NULL OR LOWER(r.attackType) LIKE :attackTypePattern)
        ORDER BY r.createdAt DESC
        """)
    Page<MlTrainingRecord> search(
            @Param("orgId")               Long   orgId,
            @Param("label")               String label,
            @Param("attackTypePattern")   String attackTypePattern,
            Pageable pageable);

    @Query("""
        SELECT r FROM MlTrainingRecord r
        WHERE ((:orgId IS NULL AND r.organization IS NULL) OR r.organization.id = :orgId)
        ORDER BY r.createdAt DESC
        """)
    List<MlTrainingRecord> findAllForExport(@Param("orgId") Long orgId);

    boolean existsByAlertId(Long alertId);

    long countByOrganization_Id(Long orgId);

    @Query("""
        SELECT COUNT(r) FROM MlTrainingRecord r
        WHERE ((:orgId IS NULL AND r.organization IS NULL) OR r.organization.id = :orgId)
          AND r.trueLabel = :label
        """)
    long countByOrgAndLabel(@Param("orgId") Long orgId, @Param("label") String label);
}
