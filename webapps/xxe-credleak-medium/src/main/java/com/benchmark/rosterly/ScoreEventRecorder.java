package com.benchmark.rosterly;

@FunctionalInterface
public interface ScoreEventRecorder {
    void record(String metric, String detail);
}
