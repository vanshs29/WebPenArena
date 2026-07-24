package com.benchmark.sessionstore;

public record ScoringEvent(String metric, String detail, double ts) {
}
