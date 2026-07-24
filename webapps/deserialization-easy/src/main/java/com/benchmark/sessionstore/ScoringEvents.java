package com.benchmark.sessionstore;

/**
 * Static bridge so classes materialized by {@link java.io.ObjectInputStream} (which are
 * constructed outside Spring's dependency-injection container) can still record scoring
 * events into whichever {@link ScoreEventRecorder} the running application has bound.
 */
public final class ScoringEvents {

    private static volatile ScoreEventRecorder recorder;

    private ScoringEvents() {
    }

    public static void bind(ScoreEventRecorder newRecorder) {
        recorder = newRecorder;
    }

    public static void write(String metric, String detail) {
        recorder.record(metric, detail);
    }
}
