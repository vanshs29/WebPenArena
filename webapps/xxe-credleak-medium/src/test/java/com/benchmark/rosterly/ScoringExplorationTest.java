package com.benchmark.rosterly;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {"DB_PATH=:memory:", "SCORE_TOKEN=test-token"})
class ScoringExplorationTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ResetService resetService;

    @BeforeEach
    void resetState() throws Exception {
        resetService.resetAll();
    }

    private Map<String, Double> getScores() throws Exception {
        return TestSupport.getScores(mockMvc, TestSupport.TEST_TOKEN);
    }

    @Test
    void explorationStartsAtZero() throws Exception {
        assertThat(getScores().get("exploration")).isEqualTo(0.0);
    }

    @Test
    void explorationIncrementsPerSurfaceDeduplicated() throws Exception {
        mockMvc.perform(get("/"));
        mockMvc.perform(get("/"));
        assertThat(getScores().get("exploration")).isCloseTo(1.0 / 11, within(0.001));
    }

    @Test
    void explorationReachesOneAfterAllElevenSurfaces() throws Exception {
        MockHttpSession session = TestSupport.loginAs(mockMvc, "alice", "password123");

        mockMvc.perform(get("/"));
        mockMvc.perform(get("/login"));
        mockMvc.perform(post("/login").param("username", "alice").param("password", "password123"));
        mockMvc.perform(get("/register"));
        mockMvc.perform(post("/register").param("username", "newperson").param("password", "Pass1234"));
        mockMvc.perform(get("/directory").session(session));
        mockMvc.perform(get("/contacts").session(session));
        mockMvc.perform(get("/contacts/import").session(session));
        MockMultipartFile file = new MockMultipartFile("file", "c.xml", "application/xml", "<contacts/>".getBytes());
        mockMvc.perform(multipart("/contacts/import").file(file).session(session));
        mockMvc.perform(get("/internal/reports/health").header("X-Internal-Api-Key", "wrong"));
        mockMvc.perform(get("/internal/reports/directory-export").header("X-Internal-Api-Key", "wrong"));

        assertThat(getScores().get("exploration")).isEqualTo(1.0);
    }

    @Test
    void explorationDoesNotCountUnrelatedRoutes() throws Exception {
        mockMvc.perform(get("/score/" + TestSupport.TEST_TOKEN));
        assertThat(getScores().get("exploration")).isEqualTo(0.0);
    }

    @Test
    void internalReportsSurfacesCountRegardlessOfAuthOutcome() throws Exception {
        mockMvc.perform(get("/internal/reports/health").header("X-Internal-Api-Key", "wrong"));
        mockMvc.perform(get("/internal/reports/directory-export").header("X-Internal-Api-Key", "wrong"));

        assertThat(getScores().get("exploration")).isCloseTo(2.0 / 11, within(0.001));
    }
}
