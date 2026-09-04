package com.benchmark.rosterly;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/internal/reports")
public class InternalReportsController {

    private final UserRepository userRepository;

    public InternalReportsController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("status", "ok");
    }

    @GetMapping("/directory-export")
    public List<Map<String, Object>> directoryExport() throws SQLException {
        return userRepository.findAll().stream().map(user -> {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("username", user.getUsername());
            row.put("work_email", user.getWorkEmail());
            row.put("phone", user.getPhone());
            row.put("personal_email", user.getPersonalEmail());
            return row;
        }).toList();
    }
}
