package com.sentinelops.security;

import com.sentinelops.config.AppProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * Issues and verifies HS256 JWTs. The signing secret must be provided via the
 * JWT_SECRET environment variable and be at least 32 bytes; otherwise the
 * application refuses to start (fail closed — no insecure default).
 */
@Service
public class JwtService {

    private final AppProperties props;
    private SecretKey key;

    public JwtService(AppProperties props) {
        this.props = props;
    }

    @PostConstruct
    void init() {
        String secret = props.getSecurity().getJwtSecret();
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException(
                "JWT_SECRET must be set and at least 32 bytes. Refusing to start with a weak/empty secret.");
        }
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String issue(String subject, String role) {
        Instant now = Instant.now();
        Instant exp = now.plus(props.getSecurity().getJwtTtlMinutes(), ChronoUnit.MINUTES);
        return Jwts.builder()
                .subject(subject)
                .claim("role", role)
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .signWith(key)
                .compact();
    }

    public Claims parse(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
    }
}
