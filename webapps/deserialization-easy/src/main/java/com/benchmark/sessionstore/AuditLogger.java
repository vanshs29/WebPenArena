package com.benchmark.sessionstore;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class AuditLogger implements Serializable {

    private static final long serialVersionUID = 1L;

    private String note;

    public AuditLogger(String note) {
        this.note = note;
    }

    public String getNote() {
        return note;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        ScoringEvents.write("exploit", "AuditLogger deserialized: " + note);
    }
}
