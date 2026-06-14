package com.aisec.backend.repository;

import com.aisec.backend.entity.BlockedIp;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface BlockedIpRepository extends JpaRepository<BlockedIp, Long> {

    Optional<BlockedIp> findByIpAddressAndOrganization_Id(String ip, Long orgId);

    /** Org-scoped lookup that also matches the global (org=null) blocklist. */
    @Query("SELECT b FROM BlockedIp b WHERE b.ipAddress = :ip AND b.active = true " +
           "AND (b.organization.id = :orgId OR b.organization IS NULL)")
    Optional<BlockedIp> findActiveForLookup(@Param("ip") String ip, @Param("orgId") Long orgId);

    /**
     * Free-text search across IP and reason. Pass an empty string for {@code q}
     * (never null) — Postgres can't infer the bytea type for an untyped NULL
     * in a LIKE expression, which is why the parameter is non-nullable here.
     */
    @Query("SELECT b FROM BlockedIp b WHERE " +
           "(:orgId IS NULL OR b.organization.id = :orgId OR b.organization IS NULL) " +
           "AND (LOWER(b.ipAddress) LIKE LOWER(CONCAT('%', :q, '%')) " +
           "  OR LOWER(COALESCE(b.reason,'')) LIKE LOWER(CONCAT('%', :q, '%')))")
    Page<BlockedIp> search(@Param("orgId") Long orgId, @Param("q") String q, Pageable pageable);

    long countByActiveTrue();
    long countByOrganization_IdAndActiveTrue(Long orgId);

    /** Distinct active IP strings across all tenants — used to seed the kernel-level enforcer at boot. */
    @Query("SELECT DISTINCT b.ipAddress FROM BlockedIp b WHERE b.active = true")
    java.util.List<String> findAllActiveIps();

    @Modifying
    @Query("UPDATE BlockedIp b SET b.sourceAlert = null WHERE b.sourceAlert.id = :alertId")
    void detachSourceAlert(@Param("alertId") Long alertId);
}
