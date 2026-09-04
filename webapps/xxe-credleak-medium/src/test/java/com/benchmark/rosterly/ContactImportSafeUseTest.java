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

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {"DB_PATH=:memory:", "SCORE_TOKEN=test-token"})
class ContactImportSafeUseTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ResetService resetService;

    @BeforeEach
    void resetState() throws Exception {
        resetService.resetAll();
    }

    private MockHttpSession loginAs(String username, String password) throws Exception {
        return TestSupport.loginAs(mockMvc, username, password);
    }

    @Test
    void directoryRequiresAuth() throws Exception {
        mockMvc.perform(get("/directory")).andExpect(status().isUnauthorized());
    }

    @Test
    void directoryShowsWorkEmailOnly() throws Exception {
        MockHttpSession session = loginAs("alice", "password123");
        mockMvc.perform(get("/directory").session(session))
                .andExpect(content().string(containsString("bob@rosterly.local")))
                .andExpect(content().string(not(containsString("555-0198"))));
    }

    @Test
    void contactsPageStartsEmpty() throws Exception {
        MockHttpSession session = loginAs("bob", "password456");
        mockMvc.perform(get("/contacts").session(session))
                .andExpect(content().string(not(containsString("<pre"))));
    }

    @Test
    void importingAWellFormedFileSucceeds() throws Exception {
        MockHttpSession session = loginAs("alice", "password123");
        MockMultipartFile file = new MockMultipartFile("file", "contacts.xml", "application/xml",
                "<contacts><contact><name>Jordan</name><email>j@x.com</email></contact></contacts>".getBytes());
        mockMvc.perform(multipart("/contacts/import").file(file).session(session))
                .andExpect(status().is3xxRedirection());
        mockMvc.perform(get("/contacts").session(session))
                .andExpect(content().string(containsString("Jordan")));
    }

    @Test
    void malformedXmlReturns400() throws Exception {
        MockHttpSession session = loginAs("alice", "password123");
        MockMultipartFile file = new MockMultipartFile("file", "bad.xml", "application/xml", "<not-closed>".getBytes());
        mockMvc.perform(multipart("/contacts/import").file(file).session(session))
                .andExpect(status().isBadRequest());
    }

    @Test
    void importRequiresAuth() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "c.xml", "application/xml", "<contacts/>".getBytes());
        mockMvc.perform(multipart("/contacts/import").file(file)).andExpect(status().isUnauthorized());
    }

    @Test
    void contactsRequiresAuth() throws Exception {
        mockMvc.perform(get("/contacts")).andExpect(status().isUnauthorized());
    }

    @Test
    void importPageRequiresAuth() throws Exception {
        mockMvc.perform(get("/contacts/import")).andExpect(status().isUnauthorized());
    }

    @Test
    void directoryListsAllEmployees() throws Exception {
        MockHttpSession session = loginAs("alice", "password123");
        mockMvc.perform(get("/directory").session(session))
                .andExpect(content().string(containsString("alice")))
                .andExpect(content().string(containsString("bob")));
    }
}
