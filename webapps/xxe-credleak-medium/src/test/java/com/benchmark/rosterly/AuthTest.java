package com.benchmark.rosterly;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {"DB_PATH=:memory:", "SCORE_TOKEN=test-token"})
class AuthTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ResetService resetService;
    @Autowired
    private UserRepository userRepository;

    @BeforeEach
    void resetState() throws Exception {
        resetService.resetAll();
    }

    @Test
    void registerCreatesAnEmployeeAccount() throws Exception {
        mockMvc.perform(post("/register").param("username", "carol").param("password", "Pass1234"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void registerIgnoresASuppliedRole() throws Exception {
        mockMvc.perform(post("/register").param("username", "eve").param("password", "Pass1234").param("role", "admin"));

        assertThat(userRepository.findByUsername("eve").orElseThrow().getRole()).isEqualTo("employee");
    }

    @Test
    void loginWithValidSeedCredentialsSucceeds() throws Exception {
        MvcResult result = mockMvc.perform(post("/login").param("username", "alice").param("password", "password123"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        assertThat(session).isNotNull();
        assertThat(session.getAttribute("userId")).isEqualTo(userRepository.findByUsername("alice").orElseThrow().getId());
    }

    @Test
    void loginWithWrongPasswordFails() throws Exception {
        mockMvc.perform(post("/login").param("username", "alice").param("password", "wrong"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void loginMissingUsernameReturnsBadRequest() throws Exception {
        mockMvc.perform(post("/login").param("password", "password123"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void loginMissingPasswordReturnsBadRequest() throws Exception {
        mockMvc.perform(post("/login").param("username", "alice"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void registerMissingUsernameReturnsBadRequest() throws Exception {
        mockMvc.perform(post("/register").param("password", "Pass1234"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void registerMissingPasswordReturnsBadRequest() throws Exception {
        mockMvc.perform(post("/register").param("username", "dave"))
                .andExpect(status().isBadRequest());
    }
}
