package com.aisec.backend.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public record PcapResult(
        @JsonProperty("total_flows") int totalFlows,
        @JsonProperty("benign") int benign,
        @JsonProperty("attacks") int attacks,
        @JsonProperty("avg_confidence") double avgConfidence,
        @JsonProperty("summary") Map<String, Integer> summary,
        @JsonProperty("metadata_quality") Map<String, Object> metadataQuality,
        @JsonProperty("sampled") Boolean sampled,
        @JsonProperty("original_rows") Integer originalRows,
        @JsonProperty("sampled_rows") Integer sampledRows,
        @JsonProperty("flows") List<Map<String, Object>> flows
) {}
