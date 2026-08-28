package com.benchmark.sessionstore;

import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;

@Component
public class SessionCookieCodec {

    public String encode(UserSession session) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(session);
        }
        return Base64.getEncoder().encodeToString(bos.toByteArray());
    }

    public UserSession decode(String cookieValue) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cookieValue);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            return (UserSession) ois.readObject();
        }
    }
}
