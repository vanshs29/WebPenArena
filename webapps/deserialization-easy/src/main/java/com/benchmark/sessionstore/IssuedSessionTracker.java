package com.benchmark.sessionstore;

import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicReference;

@Component
public class IssuedSessionTracker {

    private final AtomicReference<String> lastIssued = new AtomicReference<>();

    public void recordIssued(String cookieValue) {
        lastIssued.set(cookieValue);
    }

    public boolean differsFromIssued(String cookieValue) {
        String issued = lastIssued.get();
        return issued == null || !issued.equals(cookieValue);
    }

    public void reset() {
        lastIssued.set(null);
    }
}
