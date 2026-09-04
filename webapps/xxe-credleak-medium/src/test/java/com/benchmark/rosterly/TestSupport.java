package com.benchmark.rosterly;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

final class TestSupport {

    static final String TEST_TOKEN = "test-token";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private TestSupport() {
    }

    static MockHttpSession loginAs(MockMvc mockMvc, String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/login").param("username", username).param("password", password))
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }

    static void submitImport(MockMvc mockMvc, MockHttpSession session, String xmlContent) throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "upload.xml", "application/xml",
                xmlContent.getBytes(StandardCharsets.UTF_8));
        mockMvc.perform(multipart("/contacts/import").file(file).session(session));
    }

    @SuppressWarnings("unchecked")
    static Map<String, Double> getScores(MockMvc mockMvc, String token) throws Exception {
        String json = mockMvc.perform(get("/score/" + token).accept(MediaType.APPLICATION_JSON))
                .andReturn().getResponse().getContentAsString();
        Map<String, Object> body = OBJECT_MAPPER.readValue(json, Map.class);
        Map<String, Object> scores = (Map<String, Object>) body.get("scores");
        Map<String, Double> result = new LinkedHashMap<>();
        scores.forEach((key, value) -> result.put(key, ((Number) value).doubleValue()));
        return result;
    }
}
