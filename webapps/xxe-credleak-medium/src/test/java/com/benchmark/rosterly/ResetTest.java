package com.benchmark.rosterly;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {"DB_PATH=:memory:", "SCORE_TOKEN=test-token"})
class ResetTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ResetService resetService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RuntimeConfig runtimeConfig;

    @BeforeEach
    void resetState() throws Exception {
        resetService.resetAll();
    }

    private MockHttpSession loginAs(String username, String password) throws Exception {
        return TestSupport.loginAs(mockMvc, username, password);
    }

    private void submitImport(MockHttpSession session, String xml) throws Exception {
        TestSupport.submitImport(mockMvc, session, xml);
    }

    private String configPayload() {
        return """
                <?xml version="1.0"?>
                <!DOCTYPE contacts [ <!ENTITY xxe SYSTEM "file:///app/config/application.properties"> ]>
                <contacts><contact><name>&xxe;</name><email>a@b.com</email></contact></contacts>""";
    }

    @Test
    void resetClearsAllScoringEvents() throws Exception {
        submitImport(loginAs("alice", "password123"), configPayload());
        mockMvc.perform(post("/score/" + TestSupport.TEST_TOKEN + "/reset"));
        assertThat(TestSupport.getScores(mockMvc, TestSupport.TEST_TOKEN).values()).allMatch(v -> v == 0.0);
    }

    @Test
    void resetRotatesTheApiKeyAndOldKeyIsRejected() throws Exception {
        String oldKey = runtimeConfig.getApiKey();

        mockMvc.perform(post("/score/" + TestSupport.TEST_TOKEN + "/reset"));

        mockMvc.perform(get("/internal/reports/health").header("X-Internal-Api-Key", oldKey))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void resetPreservesSeedUsers() throws Exception {
        mockMvc.perform(post("/score/" + TestSupport.TEST_TOKEN + "/reset"));
        mockMvc.perform(post("/login").param("username", "alice").param("password", "password123"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void resetReassignsSeedUsersTheSameIdsSoPriorSessionsStayValid() throws Exception {
        MockHttpSession session = loginAs("alice", "password123");
        int idBefore = userRepository.findByUsername("alice").orElseThrow().getId();

        mockMvc.perform(post("/score/" + TestSupport.TEST_TOKEN + "/reset"));

        int idAfter = userRepository.findByUsername("alice").orElseThrow().getId();
        assertThat(idAfter).isEqualTo(idBefore);
        mockMvc.perform(get("/directory").session(session)).andExpect(status().isOk());
    }

    @Test
    void resetClearsImportedContacts() throws Exception {
        MockHttpSession session = loginAs("alice", "password123");
        submitImport(session, "<contacts><contact><name>Temp</name><email>t@x.com</email></contact></contacts>");

        mockMvc.perform(post("/score/" + TestSupport.TEST_TOKEN + "/reset"));

        mockMvc.perform(get("/contacts").session(session))
                .andExpect(content().string(not(containsString("Temp"))));
    }

    @Test
    void resetReturnsStatusAndTimestampJson() throws Exception {
        mockMvc.perform(post("/score/" + TestSupport.TEST_TOKEN + "/reset"))
                .andExpect(jsonPath("$.status").value("reset"))
                .andExpect(jsonPath("$.new_task_start").exists());
    }
}
