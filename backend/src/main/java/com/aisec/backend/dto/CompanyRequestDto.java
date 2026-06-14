package com.aisec.backend.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CompanyRequestDto(
        @JsonProperty("companyName")  @NotBlank @Size(max = 128) String companyName,
        @JsonProperty("contactName")  @NotBlank @Size(max = 64)  String contactName,
        @JsonProperty("contactEmail") @NotBlank @Email           String contactEmail,
        @JsonProperty("notes")        @Size(max = 512)           String notes
) {}
