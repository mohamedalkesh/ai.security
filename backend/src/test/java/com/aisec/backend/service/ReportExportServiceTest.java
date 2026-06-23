package com.aisec.backend.service;

import com.aisec.backend.entity.Alert;
import com.aisec.backend.entity.AlertStatus;
import com.aisec.backend.entity.Severity;
import com.aisec.backend.repository.AlertRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ReportExportService} single-alert PDF reports.
 *
 * Focus areas:
 *   - tenant org-scoping (mismatch must 404, never leak another tenant's alert)
 *   - happy path produces a well-formed PDF (magic header %PDF)
 *
 * The alert is created on the system tenant (organization == null) so the
 * happy-path caller uses orgId = null, which matches the scoping rule
 * "(orgId IS NULL AND organization IS NULL)".
 */
@ExtendWith(MockitoExtension.class)
class ReportExportServiceTest {

    @Mock AlertRepository alerts;
    @Mock AlertService alertService;

    ReportExportService service;

    private Alert sampleAlert;

    @BeforeEach
    void init() {
        service = new ReportExportService(alerts, alertService);

        sampleAlert = new Alert();
        sampleAlert.setAttackType("DDoS");
        sampleAlert.setSeverity(Severity.HIGH);
        sampleAlert.setStatus(AlertStatus.NEW);
        sampleAlert.setSourceIp("10.0.0.1");
        sampleAlert.setDestIp("10.0.0.2");
        sampleAlert.setConfidence(0.91);
        sampleAlert.setDescription("High-volume traffic flood detected");
        // organization stays null -> system tenant
    }

    private static void assertIsPdf(byte[] pdf) {
        assertThat(pdf).isNotEmpty();
        // Every PDF file starts with the bytes "%PDF"
        assertThat(new String(pdf, 0, 4)).isEqualTo("%PDF");
    }

    /* ---------------------- Response Plan ---------------------- */

    @Test
    void responsePlan_throws_404_when_alert_missing() {
        when(alerts.findById(99L)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.buildResponsePlanPdf(99L, null))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Alert not found");
    }

    @Test
    void responsePlan_throws_404_on_org_mismatch() {
        // alert belongs to system tenant (org == null) but caller is org 7 -> no access
        when(alerts.findById(1L)).thenReturn(Optional.of(sampleAlert));
        assertThatThrownBy(() -> service.buildResponsePlanPdf(1L, 7L))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Alert not found");
    }

    @Test
    void responsePlan_produces_pdf_for_matching_tenant() throws Exception {
        when(alerts.findById(1L)).thenReturn(Optional.of(sampleAlert));
        byte[] pdf = service.buildResponsePlanPdf(1L, null);
        assertIsPdf(pdf);
    }

    /* ---------------------- MITRE Mapping ---------------------- */

    @Test
    void mitre_throws_404_on_org_mismatch() {
        when(alerts.findById(2L)).thenReturn(Optional.of(sampleAlert));
        assertThatThrownBy(() -> service.buildMitrePdf(2L, 7L))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Alert not found");
    }

    @Test
    void mitre_produces_pdf_for_matching_tenant() throws Exception {
        when(alerts.findById(2L)).thenReturn(Optional.of(sampleAlert));
        byte[] pdf = service.buildMitrePdf(2L, null);
        assertIsPdf(pdf);
    }

    /* ------------------- AI Classification --------------------- */

    @Test
    void classification_throws_404_on_org_mismatch() {
        when(alerts.findById(3L)).thenReturn(Optional.of(sampleAlert));
        assertThatThrownBy(() -> service.buildClassificationPdf(3L, 7L))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("Alert not found");
    }

    @Test
    void classification_produces_pdf_for_matching_tenant() throws Exception {
        when(alerts.findById(3L)).thenReturn(Optional.of(sampleAlert));
        byte[] pdf = service.buildClassificationPdf(3L, null);
        assertIsPdf(pdf);
    }
}
