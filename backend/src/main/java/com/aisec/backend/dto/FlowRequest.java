package com.aisec.backend.dto;

import jakarta.validation.constraints.NotNull;

import java.util.Map;

public record FlowRequest(@NotNull Map<String, Double> features) {}
