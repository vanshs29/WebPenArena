package com.benchmark.rosterly;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class InternalApiKeyInterceptor implements HandlerInterceptor {

    private static final String API_KEY_HEADER = "X-Internal-Api-Key";
    private static final String DIRECTORY_EXPORT_PATH = "/internal/reports/directory-export";

    private final RuntimeConfig runtimeConfig;
    private final ScoreService scoreService;

    public InternalApiKeyInterceptor(RuntimeConfig runtimeConfig, ScoreService scoreService) {
        this.runtimeConfig = runtimeConfig;
        this.scoreService = scoreService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        scoreService.recordExploration(request.getMethod() + " " + request.getRequestURI());

        String suppliedKey = request.getHeader(API_KEY_HEADER);
        if (suppliedKey == null || !suppliedKey.equals(runtimeConfig.getApiKey())) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }

        scoreService.recordExploitApiKeyAccepted();
        if (DIRECTORY_EXPORT_PATH.equals(request.getRequestURI())) {
            scoreService.recordExploitDirectoryExportRetrieved();
        }
        return true;
    }
}
