package com.aisec.backend.service;

import com.aisec.backend.dto.alert.AlertDto;
import com.aisec.backend.entity.Alert;
import com.aisec.backend.entity.AlertStatus;
import com.aisec.backend.entity.Severity;
import com.aisec.backend.repository.AlertRepository;
import com.aisec.backend.websocket.AlertBroadcaster;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link AlertService} with a mocked repository and broadcaster.
 * All operations are exercised with orgId=null (the system tenant).
 */
@ExtendWith(MockitoExtension.class)
class AlertServiceTest {

    @Mock AlertRepository repo;
    @Mock AlertBroadcaster broadcaster;
    @InjectMocks AlertService service;

    private Alert sampleAlert;

    @BeforeEach
    void init() {
        sampleAlert = new Alert();
        sampleAlert.setAttackType("DDoS");
        sampleAlert.setSeverity(Severity.HIGH);
        sampleAlert.setStatus(AlertStatus.NEW);
        sampleAlert.setSourceIp("10.0.0.1");
        sampleAlert.setDestIp("10.0.0.2");
        sampleAlert.setConfidence(0.87);
        // organization stays null -> system tenant
    }

    @Test
    void get_throws_404_when_missing() {
        when(repo.findById(99L)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.get(99L, null))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Alert not found");
    }

    @Test
    void updateStatus_to_RESOLVED_stamps_resolvedAt() {
        when(repo.findById(1L)).thenReturn(Optional.of(sampleAlert));
        when(repo.save(any(Alert.class))).thenAnswer(inv -> inv.getArgument(0));

        AlertDto dto = service.updateStatus(1L, "resolved", null);

        assertThat(dto.status()).isEqualTo("RESOLVED");
        assertThat(sampleAlert.getResolvedAt()).isNotNull();
        assertThat(sampleAlert.getResolvedAt())
                .isBetween(Instant.now().minusSeconds(5), Instant.now().plusSeconds(5));
    }

    @Test
    void updateStatus_to_INVESTIGATING_does_NOT_set_resolvedAt() {
        when(repo.findById(1L)).thenReturn(Optional.of(sampleAlert));
        when(repo.save(any(Alert.class))).thenAnswer(inv -> inv.getArgument(0));

        service.updateStatus(1L, "INVESTIGATING", null);

        assertThat(sampleAlert.getStatus()).isEqualTo(AlertStatus.INVESTIGATING);
        assertThat(sampleAlert.getResolvedAt()).isNull();
    }

    @Test
    void updateStatus_rejects_invalid_enum() {
        when(repo.findById(1L)).thenReturn(Optional.of(sampleAlert));
        assertThatThrownBy(() -> service.updateStatus(1L, "NOT_A_STATUS", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void delete_throws_404_when_missing() {
        when(repo.findById(42L)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.delete(42L, null))
                .isInstanceOf(ResponseStatusException.class);
        verify(repo, never()).deleteById(any());
    }

    @Test
    void save_broadcasts_after_persisting() {
        when(repo.save(any(Alert.class))).thenAnswer(inv -> inv.getArgument(0));

        service.save(sampleAlert);

        verify(repo).save(sampleAlert);
        verify(broadcaster).broadcast(any(AlertDto.class), isNull());
    }

    @Test
    void list_filters_by_severity_when_provided() {
        Page<Alert> page = new PageImpl<>(List.of(sampleAlert));
        when(repo.findScopedBySeverity(isNull(), eq(Severity.HIGH), eq(PageRequest.of(0, 10))))
                .thenReturn(page);

        Page<AlertDto> result = service.list("high", null, null, PageRequest.of(0, 10));

        assertThat(result.getContent()).hasSize(1);
        assertThat(result.getContent().get(0).severity()).isEqualTo("HIGH");
    }

    @Test
    void stats_aggregates_scoped_counts_from_repo() {
        when(repo.countScoped(null)).thenReturn(100L);
        when(repo.countScopedByStatus(null, AlertStatus.NEW)).thenReturn(10L);
        when(repo.countScopedByStatus(null, AlertStatus.INVESTIGATING)).thenReturn(5L);
        when(repo.countScopedByStatus(null, AlertStatus.RESOLVED)).thenReturn(70L);
        when(repo.countScopedBySeverity(null, Severity.CRITICAL)).thenReturn(3L);
        when(repo.countScopedBySeverity(null, Severity.HIGH)).thenReturn(12L);
        when(repo.countScopedSince(eq((Long) null), any(Instant.class))).thenReturn(20L);

        var stats = service.stats(null);

        assertThat(stats).extracting("total").isEqualTo(100L);
        assertThat(stats).extracting("resolved").isEqualTo(70L);
        assertThat(stats).extracting("critical").isEqualTo(3L);
        assertThat(stats).extracting("high").isEqualTo(12L);
        assertThat(stats).extracting("last24h").isEqualTo(20L);
    }
}
