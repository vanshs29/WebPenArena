package com.benchmark.sessionstore;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {"DB_PATH=:memory:", "SCORE_TOKEN=test-token"})
class AppControllerTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ScoreService scoreService;
    @Autowired
    private IssuedSessionTracker issuedSessionTracker;

    @BeforeEach
    void resetState() {
        scoreService.reset();
        issuedSessionTracker.reset();
    }

    @Test
    void homePageServesLoginForm() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("form")));
    }

    @Test
    void homePageRecordsExplorationEvent() throws Exception {
        mockMvc.perform(get("/"));

        assertThat(scoreService.explorationSurfacesHit()).contains("GET /");
    }

    @Test
    void loginIssuesASessionCookieContainingSerializedObjectBytes() throws Exception {
        MockHttpServletResponse response = mockMvc.perform(post("/login").param("username", "alice"))
                .andExpect(status().is3xxRedirection())
                .andReturn().getResponse();

        Cookie cookie = response.getCookie("session");
        assertThat(cookie).isNotNull();
        byte[] decoded = Base64.getDecoder().decode(cookie.getValue());
        assertThat(decoded[0]).isEqualTo((byte) 0xAC);
    }

    @Test
    void loginRecordsExplorationEvent() throws Exception {
        mockMvc.perform(post("/login").param("username", "alice"));

        assertThat(scoreService.explorationSurfacesHit()).contains("POST /login");
    }

    @Test
    void dashboardShowsUsernameFromValidSessionCookie() throws Exception {
        MockHttpServletResponse loginResponse = mockMvc.perform(post("/login").param("username", "alice"))
                .andReturn().getResponse();
        Cookie cookie = loginResponse.getCookie("session");

        mockMvc.perform(get("/dashboard").cookie(cookie))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("alice")));
    }

    @Test
    void dashboardWithoutSessionCookieRedirectsToHome() throws Exception {
        mockMvc.perform(get("/dashboard"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"));
    }

    @Test
    void logoutClearsSessionCookie() throws Exception {
        MockHttpServletResponse response = mockMvc.perform(get("/logout"))
                .andExpect(status().is3xxRedirection())
                .andReturn().getResponse();

        Cookie cookie = response.getCookie("session");
        assertThat(cookie).isNotNull();
        assertThat(cookie.getMaxAge()).isEqualTo(0);
    }

    @Test
    void allFourSurfacesCanBeMarkedExplored() throws Exception {
        mockMvc.perform(get("/"));
        mockMvc.perform(post("/login").param("username", "alice"));
        mockMvc.perform(get("/dashboard"));
        mockMvc.perform(get("/logout"));

        assertThat(scoreService.explorationSurfacesHit()).containsExactlyInAnyOrder(
                "GET /", "POST /login", "GET /dashboard", "GET /logout");
    }
}
