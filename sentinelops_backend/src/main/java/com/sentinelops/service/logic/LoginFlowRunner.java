package com.sentinelops.service.logic;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelops.entity.SessionType;
import com.sentinelops.entity.TestIdentity;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Runs one login attempt for a {@link TestIdentity} and captures whether a session was issued.
 * Used first by the "test login" check, and later by the auth/IDOR/checkout modules (phases 1, 2, 4) to
 * obtain a fresh session before replaying requests as that identity. The raw session value is returned
 * only to in-process callers (other services); it must never be serialized back to an API response.
 */
@Component
public class LoginFlowRunner {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** {@code sessionValue} is the bearer token or the raw Set-Cookie value; null when none was captured. */
    public record LoginOutcome(boolean success, int httpStatus, boolean sessionCaptured, String sessionValue, String detail) {
        public static LoginOutcome failed(int status, String detail) {
            return new LoginOutcome(false, status, false, null, detail);
        }
    }

    private final LoginHttpClient http;

    public LoginFlowRunner(LoginHttpClient http) {
        this.http = http;
    }

    public LoginOutcome attempt(TestIdentity identity, String plainPassword) {
        String body;
        try {
            body = JSON.createObjectNode()
                    .put(identity.getUsernameField(), identity.getUsername())
                    .put(identity.getPasswordField(), plainPassword)
                    .toString();
        } catch (Exception ex) {
            return LoginOutcome.failed(0, "Could not build the login request.");
        }

        LoginHttpClient.Response res;
        try {
            res = http.post(identity.getLoginUrl(), body);
        } catch (Exception ex) {
            return LoginOutcome.failed(0, "The login request could not be sent: " + ex.getClass().getSimpleName());
        }

        if (res.status() < 200 || res.status() >= 300) {
            return LoginOutcome.failed(res.status(), "Login was refused (HTTP " + res.status() + "). "
                    + "Check the field names and the account's credentials.");
        }

        if (identity.getSessionType() == SessionType.COOKIE) {
            List<String> setCookie = res.headers().getOrDefault("set-cookie", List.of());
            if (setCookie.isEmpty()) {
                return new LoginOutcome(false, res.status(), false, null,
                        "Login succeeded (HTTP " + res.status() + ") but no Set-Cookie header was returned.");
            }
            return new LoginOutcome(true, res.status(), true, setCookie.get(0),
                    "Login succeeded and a session cookie was captured.");
        }

        // HEADER_BEARER: pull the token out of the JSON body at the configured dot-path.
        String path = identity.getTokenPath() == null || identity.getTokenPath().isBlank() ? "token" : identity.getTokenPath();
        JsonNode node;
        try {
            node = JSON.readTree(res.body());
        } catch (Exception ex) {
            return new LoginOutcome(false, res.status(), false, null,
                    "Login succeeded (HTTP " + res.status() + ") but the response was not JSON.");
        }
        for (String part : path.split("\\.")) {
            if (part.isBlank()) continue;
            node = node.path(part);
        }
        if (!node.isTextual() || node.asText().isBlank()) {
            return new LoginOutcome(false, res.status(), false, null,
                    "Login succeeded (HTTP " + res.status() + ") but no token was found at \"" + path + "\" in the response.");
        }
        return new LoginOutcome(true, res.status(), true, node.asText(), "Login succeeded and a token was captured.");
    }
}
