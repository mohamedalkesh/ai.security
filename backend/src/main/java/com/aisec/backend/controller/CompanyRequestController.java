package com.aisec.backend.controller;

import com.aisec.backend.dto.CompanyRequestDto;
import com.aisec.backend.service.CompanyRequestService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class CompanyRequestController {

    private final CompanyRequestService service;

    public CompanyRequestController(CompanyRequestService service) {
        this.service = service;
    }

    @PostMapping("/company-request")
    public ResponseEntity<Void> submit(@Valid @RequestBody CompanyRequestDto request) {
        service.submitRequest(request);
        return ResponseEntity.ok().build();
    }
}
