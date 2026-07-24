package com.benchmark.sessionstore;

import java.io.Serializable;

public class UserSession implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String username;
    private final String role;
    private final String theme;

    public UserSession(String username, String role, String theme) {
        this.username = username;
        this.role = role;
        this.theme = theme;
    }

    public String getUsername() {
        return username;
    }

    public String getRole() {
        return role;
    }

    public String getTheme() {
        return theme;
    }
}
