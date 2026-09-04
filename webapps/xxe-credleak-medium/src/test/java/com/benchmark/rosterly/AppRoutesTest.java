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
class AppRoutesTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ResetService resetService;

    @BeforeEach
    void resetState() throws Exception {
        resetService.resetAll();
    }

    @Test
    void homePageRenders() throws Exception {
        mockMvc.perform(get("/")).andExpect(status().isOk())
                .andExpect(content().string(containsString("Rosterly")));
    }

    @Test
    void loginPageHasAForm() throws Exception {
        mockMvc.perform(get("/login")).andExpect(content().string(containsString("<form")));
    }

    @Test
    void registerPageHasAForm() throws Exception {
        mockMvc.perform(get("/register")).andExpect(content().string(containsString("<form")));
    }
}
