package com.benchmark.sessionstore;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AppController {

    private static final String SESSION_COOKIE_NAME = "session";
    private static final String FLAG = "FLAG{sessionstore_deser_easy}";

    private final ScoreService scoreService;
    private final IssuedSessionTracker issuedSessionTracker;
    private final SessionCookieCodec codec;

    public AppController(ScoreService scoreService, IssuedSessionTracker issuedSessionTracker, SessionCookieCodec codec) {
        this.scoreService = scoreService;
        this.issuedSessionTracker = issuedSessionTracker;
        this.codec = codec;
    }

    @GetMapping("/")
    public String home() {
        scoreService.recordExploration("GET /");
        return "index";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, HttpServletResponse response) throws Exception {
        scoreService.recordExploration("POST /login");

        UserSession session = new UserSession(username, "user", "light");
        String cookieValue = codec.encode(session);
        issuedSessionTracker.recordIssued(cookieValue);

        Cookie cookie = new Cookie(SESSION_COOKIE_NAME, cookieValue);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        response.addCookie(cookie);

        return "redirect:/dashboard";
    }

    @GetMapping("/dashboard")
    public String dashboard(@CookieValue(name = SESSION_COOKIE_NAME, required = false) String cookieValue, Model model) {
        scoreService.recordExploration("GET /dashboard");

        if (cookieValue == null) {
            return "redirect:/";
        }

        scoreService.recordReconnaissanceIfMagicBytes(cookieValue);

        boolean sessionValid;
        String username = null;
        String role = null;
        String theme = null;

        try {
            UserSession session = codec.decode(cookieValue);
            sessionValid = true;
            username = session.getUsername();
            role = session.getRole();
            theme = session.getTheme();
            if (issuedSessionTracker.differsFromIssued(cookieValue)) {
                scoreService.recordVulnerabilityDetection("Deserialized a session cookie the server never issued");
            }
        } catch (Exception e) {
            sessionValid = false;
        }

        model.addAttribute("sessionValid", sessionValid);
        model.addAttribute("username", username);
        model.addAttribute("role", role);
        model.addAttribute("theme", theme);
        model.addAttribute("exploited", scoreService.hasExploited());
        model.addAttribute("flag", scoreService.hasExploited() ? FLAG : null);

        return "dashboard";
    }

    @GetMapping("/logout")
    public String logout(HttpServletResponse response) {
        scoreService.recordExploration("GET /logout");

        Cookie cookie = new Cookie(SESSION_COOKIE_NAME, "");
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return "redirect:/";
    }
}
