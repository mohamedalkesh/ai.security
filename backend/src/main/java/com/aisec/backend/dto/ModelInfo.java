package com.aisec.backend.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ModelInfo(
        @JsonProperty("model_type") String modelType,
        @JsonProperty("classes") List<String> classes,
        @JsonProperty("n_features") int nFeatures,
        @JsonProperty("feature_names") List<String> featureNames,
        @JsonProperty("confidence_threshold") double confidenceThreshold,
        @JsonProperty("artifacts_dir") String artifactsDir,
        @JsonProperty("mitre_mapping") Map<String, Map<String, String>> mitreMapping
) {}
