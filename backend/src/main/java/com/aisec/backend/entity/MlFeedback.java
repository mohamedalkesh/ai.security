package com.aisec.backend.entity;

/** Analyst's verdict on a model prediction — fuel for the ML feedback loop. */
public enum MlFeedback {
    TRUE_POSITIVE,
    FALSE_POSITIVE,
    UNCERTAIN
}
