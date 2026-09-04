package com.benchmark.rosterly;

import org.springframework.stereotype.Service;

@Service
public class ResetService {

    private final UserRepository userRepository;
    private final ContactRepository contactRepository;
    private final ScoreDatabase scoreDatabase;
    private final RuntimeConfig runtimeConfig;

    public ResetService(UserRepository userRepository, ContactRepository contactRepository,
                         ScoreDatabase scoreDatabase, RuntimeConfig runtimeConfig) {
        this.userRepository = userRepository;
        this.contactRepository = contactRepository;
        this.scoreDatabase = scoreDatabase;
        this.runtimeConfig = runtimeConfig;
    }

    public void resetAll() throws Exception {
        contactRepository.deleteAll();
        userRepository.deleteAllAndResetSequence();
        userRepository.seed();
        scoreDatabase.reset();
        runtimeConfig.rotate();
    }
}
