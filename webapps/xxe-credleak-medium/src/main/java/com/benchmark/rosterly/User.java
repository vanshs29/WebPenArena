package com.benchmark.rosterly;

public class User {

    private final int id;
    private final String username;
    private final String password;
    private final String role;
    private final String workEmail;
    private final String phone;
    private final String personalEmail;

    public User(int id, String username, String password, String role,
                String workEmail, String phone, String personalEmail) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.role = role;
        this.workEmail = workEmail;
        this.phone = phone;
        this.personalEmail = personalEmail;
    }

    public int getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getRole() {
        return role;
    }

    public String getWorkEmail() {
        return workEmail;
    }

    public String getPhone() {
        return phone;
    }

    public String getPersonalEmail() {
        return personalEmail;
    }
}
