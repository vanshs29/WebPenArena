package com.benchmark.rosterly;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {"DB_PATH=:memory:", "SCORE_TOKEN=test-token"})
class InternalReportsAuthTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ResetService resetService;
    @Autowired
    private RuntimeConfig runtimeConfig;

    @BeforeEach
    void resetState() throws Exception {
        resetService.resetAll();
    }

    private MockHttpSession loginAs(String username, String password) throws Exception {
        return TestSupport.loginAs(mockMvc, username, password);
    }

    @Test
    void missingKeyIsRejected() throws Exception {
        mockMvc.perform(get("/internal/reports/health")).andExpect(status().isUnauthorized());
    }

    @Test
    void wrongKeyIsRejected() throws Exception {
        mockMvc.perform(get("/internal/reports/health").header("X-Internal-Api-Key", "wrong"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void correctKeyUnlocksHealth() throws Exception {
        mockMvc.perform(get("/internal/reports/health").header("X-Internal-Api-Key", runtimeConfig.getApiKey()))
                .andExpect(status().isOk());
    }

    @Test
    void aUserSessionAloneDoesNotUnlockInternalReports() throws Exception {
        MockHttpSession session = loginAs("alice", "password123");
        mockMvc.perform(get("/internal/reports/health").session(session)).andExpect(status().isUnauthorized());
    }

    @Test
    void directoryExportIncludesPrivateFieldsUnderTheKey() throws Exception {
        mockMvc.perform(get("/internal/reports/directory-export").header("X-Internal-Api-Key", runtimeConfig.getApiKey()))
                .andExpect(content().string(containsString("555-0142")))
                .andExpect(content().string(containsString("alice.h.private@mailbox.example")));
    }

    @Test
    void missingKeyIsRejectedOnDirectoryExport() throws Exception {
        mockMvc.perform(get("/internal/reports/directory-export")).andExpect(status().isUnauthorized());
    }

    @Test
    void emptyKeyHeaderIsRejected() throws Exception {
        mockMvc.perform(get("/internal/reports/health").header("X-Internal-Api-Key", ""))
                .andExpect(status().isUnauthorized());
    }
}
