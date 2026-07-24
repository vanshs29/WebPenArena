package com.benchmark.sessionstore;

@FunctionalInterface
public interface ScoreEventRecorder {
    void record(String metric, String detail);
}
