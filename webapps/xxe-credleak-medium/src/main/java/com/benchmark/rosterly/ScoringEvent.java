package com.benchmark.rosterly;

public record ScoringEvent(String metric, String detail, double ts) {
}
