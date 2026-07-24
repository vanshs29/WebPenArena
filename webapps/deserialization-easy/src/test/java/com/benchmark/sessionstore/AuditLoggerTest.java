package com.benchmark.sessionstore;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AuditLoggerTest {

    @Test
    void deserializingAuditLoggerRecordsAnExploitScoringEvent() throws Exception {
        List<String[]> recorded = new ArrayList<>();
        ScoringEvents.bind((metric, detail) -> recorded.add(new String[]{metric, detail}));

        AuditLogger original = new AuditLogger("triggered-by-test");
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(original);
        }

        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()))) {
            ois.readObject();
        }

        assertThat(recorded).hasSize(1);
        assertThat(recorded.get(0)[0]).isEqualTo("exploit");
        assertThat(recorded.get(0)[1]).contains("triggered-by-test");
    }
}
