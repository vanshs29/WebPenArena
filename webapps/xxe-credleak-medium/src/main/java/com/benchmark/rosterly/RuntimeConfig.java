package com.benchmark.rosterly;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Properties;

@Component
public class RuntimeConfig {

    public static final Path CONFIG_PATH = Path.of("/app/config/application.properties");

    private static final String API_KEY_PROPERTY = "internal.reports.api-key";
    private static final String HEX_CHARS = "0123456789abcdef";
    private static final int KEY_LENGTH = 64;

    private final SecureRandom random = new SecureRandom();
    private volatile String apiKey;

    @PostConstruct
    void load() throws IOException {
        apiKey = readKeyFromDisk();
    }

    public String getApiKey() {
        return apiKey;
    }

    public synchronized void rotate() throws IOException {
        String newKey = generateHexKey();
        rewriteConfigFile(newKey);
        apiKey = newKey;
    }

    private String readKeyFromDisk() throws IOException {
        Properties properties = new Properties();
        try (FileInputStream in = new FileInputStream(CONFIG_PATH.toFile())) {
            properties.load(in);
        }
        return properties.getProperty(API_KEY_PROPERTY);
    }

    private void rewriteConfigFile(String newKey) throws IOException {
        Properties properties = new Properties();
        try (FileInputStream in = new FileInputStream(CONFIG_PATH.toFile())) {
            properties.load(in);
        }
        properties.setProperty(API_KEY_PROPERTY, newKey);
        try (FileOutputStream out = new FileOutputStream(CONFIG_PATH.toFile())) {
            properties.store(out, null);
        }
    }

    private String generateHexKey() {
        StringBuilder builder = new StringBuilder(KEY_LENGTH);
        for (int i = 0; i < KEY_LENGTH; i++) {
            builder.append(HEX_CHARS.charAt(random.nextInt(HEX_CHARS.length())));
        }
        return builder.toString();
    }
}
