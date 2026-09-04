package com.benchmark.rosterly;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {"DB_PATH=:memory:", "SCORE_TOKEN=test-token"})
class RuntimeConfigTest {

    @Autowired
    private RuntimeConfig runtimeConfig;
    @Autowired
    private ResetService resetService;

    @BeforeEach
    void resetState() throws Exception {
        resetService.resetAll();
    }

    @Test
    void loadsTheKeyPresentOnDiskAtStartup() {
        assertThat(runtimeConfig.getApiKey()).hasSize(64);
    }

    @Test
    void rotateGeneratesADifferentKeyAndRewritesTheFile() throws IOException {
        String before = runtimeConfig.getApiKey();
        runtimeConfig.rotate();
        assertThat(runtimeConfig.getApiKey()).isNotEqualTo(before);

        Properties onDisk = new Properties();
        try (FileInputStream in = new FileInputStream(RuntimeConfig.CONFIG_PATH.toFile())) {
            onDisk.load(in);
        }
        assertThat(onDisk.getProperty("internal.reports.api-key")).isEqualTo(runtimeConfig.getApiKey());
    }

    @Test
    void apiKeyIsNeverNull() {
        assertThat(runtimeConfig.getApiKey()).isNotNull();
    }

    @Test
    void consecutiveRotationsProduceDifferentKeys() throws IOException {
        runtimeConfig.rotate();
        String first = runtimeConfig.getApiKey();
        runtimeConfig.rotate();
        String second = runtimeConfig.getApiKey();
        assertThat(second).isNotEqualTo(first);
    }
}
