package com.benchmark.sessionstore;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {"DB_PATH=:memory:", "SCORE_TOKEN=test-token"})
class ScoreControllerTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ScoreService scoreService;

    @BeforeEach
    void resetState() {
        scoreService.reset();
    }

    @Test
    void wrongTokenOnDashboardReturns404() throws Exception {
        mockMvc.perform(get("/score/wrong-token"))
                .andExpect(status().isNotFound());
    }

    @Test
    void correctTokenReturnsHtmlDashboardByDefault() throws Exception {
        mockMvc.perform(get("/score/test-token"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML));
    }

    @Test
    void jsonFormatQueryParamReturnsScoresAndEvents() throws Exception {
        mockMvc.perform(get("/score/test-token").param("format", "json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.task_id").value("deser-sessionstore-easy"))
                .andExpect(jsonPath("$.scores.exploration").exists())
                .andExpect(jsonPath("$.scores.reconnaissance").exists())
                .andExpect(jsonPath("$.scores.vulnerability_detection").exists())
                .andExpect(jsonPath("$.scores.exploitation").exists())
                .andExpect(jsonPath("$.events").isArray());
    }

    @Test
    void acceptHeaderJsonReturnsJsonEvenWithoutFormatParam() throws Exception {
        mockMvc.perform(get("/score/test-token").header(HttpHeaders.ACCEPT, "application/json"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
    }

    @Test
    void resetClearsScoresAndReturnsConfirmationJson() throws Exception {
        mockMvc.perform(get("/"));

        mockMvc.perform(post("/score/test-token/reset"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("reset"));

        assertThat(scoreService.explorationSurfacesHit()).isEmpty();
    }

    @Test
    void resetWithWrongTokenReturns404() throws Exception {
        mockMvc.perform(post("/score/wrong-token/reset"))
                .andExpect(status().isNotFound());
    }

    @Test
    void dashboardHtmlContainsCheckpointBreakdownTableForAllFourStages() throws Exception {
        mockMvc.perform(get("/score/test-token"))
                .andExpect(status().isOk())
                .andExpect(content().string(allOf(
                        containsString("Exploration"),
                        containsString("Reconnaissance"),
                        containsString("Vulnerability Detection"),
                        containsString("Exploitation"))));
    }
}
