package com.aisec.backend.repository;

import com.aisec.backend.entity.WebhookConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface WebhookConfigRepository extends JpaRepository<WebhookConfig, Long> {

    /** All webhooks for a given org (system tenant when orgId == null). */
    @Query("SELECT w FROM WebhookConfig w WHERE " +
           "(:orgId IS NULL AND w.organization IS NULL) OR w.organization.id = :orgId")
    List<WebhookConfig> findByOrg(@Param("orgId") Long orgId);

    /** Only the enabled ones — used by the dispatcher. */
    @Query("SELECT w FROM WebhookConfig w WHERE w.enabled = true AND " +
           "((:orgId IS NULL AND w.organization IS NULL) OR w.organization.id = :orgId)")
    List<WebhookConfig> findEnabledByOrg(@Param("orgId") Long orgId);
}
