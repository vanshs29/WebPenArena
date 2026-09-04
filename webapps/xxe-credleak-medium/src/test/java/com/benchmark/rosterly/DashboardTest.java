package com.benchmark.rosterly;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {"DB_PATH=:memory:", "SCORE_TOKEN=test-token"})
class DashboardTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ResetService resetService;

    @BeforeEach
    void resetState() throws Exception {
        resetService.resetAll();
    }

    @Test
    void wrongTokenReturns404() throws Exception {
        mockMvc.perform(get("/score/not-real")).andExpect(status().isNotFound());
    }

    @Test
    void dashboardListsAllElevenSurfacesAndAllCheckpoints() throws Exception {
        mockMvc.perform(get("/score/" + TestSupport.TEST_TOKEN))
                .andExpect(content().string(containsString("GET /internal/reports/directory-export")))
                .andExpect(content().string(containsString("Config secret retrieved")));
    }

    @Test
    void dashboardHasAResetButtonAndJsonLink() throws Exception {
        mockMvc.perform(get("/score/" + TestSupport.TEST_TOKEN))
                .andExpect(content().string(containsString("/reset")))
                .andExpect(content().string(containsString("?format=json")));
    }

    @Test
    void dashboardShowsAllElevenExplorationSurfaceRows() throws Exception {
        mockMvc.perform(get("/score/" + TestSupport.TEST_TOKEN))
                .andExpect(content().string(containsString("POST /contacts/import")))
                .andExpect(content().string(containsString("GET /internal/reports/health")))
                .andExpect(content().string(containsString("Entity declaration attempted")))
                .andExpect(content().string(containsString("Internal API key accepted")));
    }

    @Test
    void wrongTokenReturns404OnDashboardWithFormatJson() throws Exception {
        mockMvc.perform(get("/score/not-real?format=json")).andExpect(status().isNotFound());
    }

    @Test
    void dashboardShowsPerCheckpointWeightsAndTheOverallPointCeiling() throws Exception {
        mockMvc.perform(get("/score/" + TestSupport.TEST_TOKEN))
                .andExpect(content().string(containsString("0.0 / 6.5 pts")))
                .andExpect(content().string(containsString("14.0 pts")));
    }
}
