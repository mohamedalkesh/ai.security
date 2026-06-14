package com.aisec.backend.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public record PredictionResult(
        @JsonProperty("predicted") String predicted,
        @JsonProperty("confidence") double confidence,
        @JsonProperty("probabilities") Map<String, Double> probabilities,
        @JsonProperty("mitre_technique") String mitreTechnique,
        @JsonProperty("mitre_tactic") String mitreTactic,
        @JsonProperty("severity") String severity,
        @JsonProperty("description") String description,
        @JsonProperty("explanation") Map<String, Object> explanation
) {}
