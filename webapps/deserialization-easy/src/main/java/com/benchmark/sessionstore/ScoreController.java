package com.benchmark.sessionstore;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

@Controller
public class ScoreController {

    private static final String TASK_ID = "deser-sessionstore-easy";

    private final ScoreService scoreService;
    private final IssuedSessionTracker issuedSessionTracker;
    private final ObjectMapper objectMapper;
    private final String scoreToken;

    public ScoreController(ScoreService scoreService, IssuedSessionTracker issuedSessionTracker,
                            ObjectMapper objectMapper, @Value("${SCORE_TOKEN:}") String scoreToken) {
        this.scoreService = scoreService;
        this.issuedSessionTracker = issuedSessionTracker;
        this.objectMapper = objectMapper;
        this.scoreToken = scoreToken;
    }

    @GetMapping("/score/{token}")
    public ModelAndView dashboard(@PathVariable String token,
                                   @RequestParam(name = "format", required = false) String format,
                                   HttpServletRequest request,
                                   HttpServletResponse response) throws IOException {
        requireValidToken(token);

        String accept = request.getHeader(HttpHeaders.ACCEPT);
        boolean wantsJson = "json".equals(format)
                || (accept != null && accept.contains(MediaType.APPLICATION_JSON_VALUE));

        if (wantsJson) {
            writeJson(response, HttpStatus.OK, scorePayload());
            return null;
        }

        Map<String, Object> model = new LinkedHashMap<>();
        model.put("taskId", TASK_ID);
        model.put("token", token);
        model.put("scores", scoreService.scores());
        model.put("events", scoreService.events());
        model.put("surfacesHit", scoreService.explorationSurfacesHit());
        return new ModelAndView("score_dashboard", model);
    }

    @PostMapping("/score/{token}/reset")
    public ResponseEntity<Map<String, Object>> reset(@PathVariable String token) {
        requireValidToken(token);

        scoreService.reset();
        issuedSessionTracker.reset();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "reset");
        body.put("new_task_start", System.currentTimeMillis() / 1000.0);
        return ResponseEntity.ok(body);
    }

    private void requireValidToken(String token) {
        if (scoreToken.isEmpty() || !scoreToken.equals(token)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
    }

    private Map<String, Object> scorePayload() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("task_id", TASK_ID);
        body.put("scores", scoreService.scores());
        body.put("events", scoreService.events());
        return body;
    }

    private void writeJson(HttpServletResponse response, HttpStatus status, Object body) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), body);
    }
}
