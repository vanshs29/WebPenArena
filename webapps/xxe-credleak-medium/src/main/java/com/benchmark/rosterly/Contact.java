package com.benchmark.rosterly;

public class Contact {

    private final int id;
    private final int ownerId;
    private final String name;
    private final String email;

    public Contact(int id, int ownerId, String name, String email) {
        this.id = id;
        this.ownerId = ownerId;
        this.name = name;
        this.email = email;
    }

    public int getId() {
        return id;
    }

    public int getOwnerId() {
        return ownerId;
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }
}
