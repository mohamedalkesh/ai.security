package com.aisec.backend.repository;

import com.aisec.backend.entity.ScanResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ScanResultRepository extends JpaRepository<ScanResult, Long> {

    @Query("SELECT s FROM ScanResult s WHERE (:orgId IS NULL AND s.organization IS NULL) OR s.organization.id = :orgId ORDER BY s.createdAt DESC")
    List<ScanResult> findRecentByOrg(@Param("orgId") Long orgId);
}
