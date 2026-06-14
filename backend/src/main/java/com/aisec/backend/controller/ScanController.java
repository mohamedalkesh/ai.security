package com.aisec.backend.controller;

import com.aisec.backend.dto.FlowRequest;
import com.aisec.backend.dto.ModelInfo;
import com.aisec.backend.dto.PredictionResult;
import com.aisec.backend.dto.scan.ScanSummaryDto;
import com.aisec.backend.security.OrgUserDetails;
import com.aisec.backend.service.MlClient;
import com.aisec.backend.service.ScanService;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/api")
public class ScanController {

    private final MlClient ml;
    private final ScanService scans;

    public ScanController(MlClient ml, ScanService scans) {
        this.ml = ml;
        this.scans = scans;
    }

    @GetMapping("/model/info")
    public ModelInfo modelInfo() { return ml.modelInfo(); }

    @PostMapping("/predict/flow")
    public PredictionResult predictFlow(@Valid @RequestBody FlowRequest req,
                                        @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return scans.handleFlow(req.features(), orgId);
    }

    @PostMapping(value = "/predict/pcap", consumes = "multipart/form-data")
    public ScanSummaryDto predictPcap(@RequestParam("file") MultipartFile file,
                                      @AuthenticationPrincipal OrgUserDetails principal) throws IOException {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return scans.handlePcap(file, orgId);
    }

    @GetMapping("/scans")
    public List<ScanSummaryDto> recent(@AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return scans.recent(orgId);
    }

    @GetMapping("/scans/{id}")
    public ScanSummaryDto getScan(@PathVariable Long id,
                                  @AuthenticationPrincipal OrgUserDetails principal) {
        Long orgId = principal != null ? principal.getOrganizationId() : null;
        return scans.findOne(id, orgId);
    }
}
