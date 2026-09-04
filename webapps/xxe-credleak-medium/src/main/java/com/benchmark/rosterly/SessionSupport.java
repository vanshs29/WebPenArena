package com.benchmark.rosterly;

import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

@Component
public class SessionSupport {

    private static final String USER_ID_ATTRIBUTE = "userId";

    public int requireAuth(HttpSession session) {
        Object userId = session.getAttribute(USER_ID_ATTRIBUTE);
        if (userId == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        return (int) userId;
    }

    public void login(HttpSession session, int userId) {
        session.setAttribute(USER_ID_ATTRIBUTE, userId);
    }
}
