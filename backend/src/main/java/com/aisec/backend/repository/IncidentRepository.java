package com.aisec.backend.repository;

import com.aisec.backend.entity.AlertStatus;
import com.aisec.backend.entity.Incident;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface IncidentRepository extends JpaRepository<Incident, Long> {

    Optional<Incident> findByCorrelationKey(String key);

    @Query("SELECT i FROM Incident i WHERE i.correlationKey = :k AND i.status IN :open")
    Optional<Incident> findOpenByCorrelationKey(@Param("k") String key,
                                                @Param("open") java.util.List<AlertStatus> openStatuses);

    @Query("SELECT i FROM Incident i WHERE (:orgId IS NULL AND i.organization IS NULL) OR i.organization.id = :orgId")
    Page<Incident> findScoped(@Param("orgId") Long orgId, Pageable pageable);

    @Query("SELECT COUNT(i) FROM Incident i WHERE ((:orgId IS NULL AND i.organization IS NULL) OR i.organization.id = :orgId) AND i.status = :status")
    long countScopedByStatus(@Param("orgId") Long orgId, @Param("status") AlertStatus status);

    /** All open incidents whose source IP matches — used by firewall auto-resolve. */
    @Query("SELECT i FROM Incident i WHERE i.sourceIp = :ip AND i.status IN :open AND " +
           "((:orgId IS NULL AND i.organization IS NULL) OR i.organization.id = :orgId)")
    java.util.List<Incident> findOpenBySourceIp(@Param("ip") String ip,
                                                 @Param("orgId") Long orgId,
                                                 @Param("open") java.util.List<AlertStatus> open);
}
