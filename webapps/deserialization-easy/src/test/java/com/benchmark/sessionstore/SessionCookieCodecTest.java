package com.benchmark.sessionstore;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SessionCookieCodecTest {

    private final SessionCookieCodec codec = new SessionCookieCodec();

    @Test
    void roundTripsUserSessionFieldsThroughEncodeAndDecode() throws Exception {
        UserSession original = new UserSession("alice", "user", "light");

        String cookieValue = codec.encode(original);
        UserSession decoded = codec.decode(cookieValue);

        assertThat(decoded.getUsername()).isEqualTo("alice");
        assertThat(decoded.getRole()).isEqualTo("user");
        assertThat(decoded.getTheme()).isEqualTo("light");
    }

    @Test
    void encodedCookieValueIsBase64OfJavaSerializedBytes() throws Exception {
        String cookieValue = codec.encode(new UserSession("bob", "user", "dark"));

        byte[] decodedBytes = Base64.getDecoder().decode(cookieValue);

        assertThat(decodedBytes[0]).isEqualTo((byte) 0xAC);
        assertThat(decodedBytes[1]).isEqualTo((byte) 0xED);
        assertThat(decodedBytes[2]).isEqualTo((byte) 0x00);
        assertThat(decodedBytes[3]).isEqualTo((byte) 0x05);
    }

    @Test
    void decodeRejectsInvalidBase64() {
        assertThrows(IllegalArgumentException.class, () -> codec.decode("not-valid-base64!!!"));
    }

    @Test
    void decodeAcceptsAnyStructurallyValidSerializedUserSessionRegardlessOfOrigin() throws Exception {
        UserSession forged = new UserSession("mallory", "admin", "dark");
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(forged);
        }
        String forgedCookieValue = Base64.getEncoder().encodeToString(bos.toByteArray());

        UserSession decoded = codec.decode(forgedCookieValue);

        assertThat(decoded.getRole()).isEqualTo("admin");
    }
}
