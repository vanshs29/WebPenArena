package com.benchmark.sessionstore;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Bean
    public ScoreDatabase scoreDatabase(@Value("${DB_PATH:sessionstore.db}") String dbPath) throws Exception {
        return new ScoreDatabase("jdbc:sqlite:" + dbPath);
    }
}
