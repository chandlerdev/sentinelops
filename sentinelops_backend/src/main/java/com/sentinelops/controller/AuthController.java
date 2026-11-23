package com.sentinelops.controller;

import com.sentinelops.entity.User;
import com.sentinelops.dto.LoginRequest;
import com.sentinelops.dto.LoginResponse;
import com.sentinelops.config.AppProperties;
import com.sentinelops.repository.UserRepository;
import com.sentinelops.security.JwtService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwt;
    private final AppProperties props;

    public AuthController(UserRepository users, PasswordEncoder encoder,
                          JwtService jwt, AppProperties props) {
        this.users = users;
        this.encoder = encoder;
        this.jwt = jwt;
        this.props = props;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req) {
        // Uniform failure: do not reveal whether the email exists.
        User user = users.findByEmail(req.email()).orElse(null);
        if (user == null || !user.isActive() || !encoder.matches(req.password(), user.getPassword())) {
            return ResponseEntity.status(401).body(new ErrorResponse("Invalid credentials"));
        }
        String token = jwt.issue(user.getEmail(), user.getRole().name());
        return ResponseEntity.ok(new LoginResponse(
                token, user.getRole().name(), props.getSecurity().getJwtTtlMinutes()));
    }

    record ErrorResponse(String error) {}
}
