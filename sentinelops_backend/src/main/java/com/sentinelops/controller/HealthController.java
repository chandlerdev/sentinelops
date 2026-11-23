package com.sentinelops.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Public liveness/readiness endpoint used by the status page and deployment checks.
 * Exposes no sensitive data: only UP/DOWN for the app and its database.
 */
@RestController
@RequestMapping("/api/health")
public class HealthController {

    private final JdbcTemplate jdbc;
    private final String appName;
    private final String version;

    public HealthController(JdbcTemplate jdbc,
                            @Value("${spring.application.name:sentinelops}") String appName,
                            @Value("${sentinelops.version:0.3.0}") String version) {
        this.jdbc = jdbc;
        this.appName = appName;
        this.version = version;
    }

    @GetMapping
    public Map<String, Object> health() {
        String db;
        try {
            jdbc.queryForObject("SELECT 1", Integer.class);
            db = "UP";
        } catch (Exception e) {
            db = "DOWN";
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "UP");
        out.put("service", appName);
        out.put("version", version);
        out.put("database", db);
        out.put("time", Instant.now().toString());
        return out;
    }
}
