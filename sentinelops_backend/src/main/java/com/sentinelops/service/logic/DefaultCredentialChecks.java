package com.sentinelops.service.logic;

import com.sentinelops.entity.Severity;
import com.sentinelops.entity.TestIdentity;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Phase 5 of the logic-testing engine (NET-07: default service credentials). Reuses an existing test
 * identity's login shape (URL, field names, session type) but ignores its stored username/password,
 * trying a small, well-known candidate list instead. Stops at the first pair a real session is issued for
 * — that is the only evidence that counts, never a guess from a response that merely "looks different".
 */
@Component
public class DefaultCredentialChecks {

    public enum Verdict { VULNERABLE, NOT_VULNERABLE, NEEDS_MANUAL_REVIEW }

    public record Result(String checkId, String title, Verdict verdict, Severity severity, String location,
                         String description, String remediation) {}

    /** Deliberately short: this is a hygiene spot-check, not a brute-force tool. */
    private static final List<Map.Entry<String, String>> CANDIDATES = List.of(
            Map.entry("admin", "admin"), Map.entry("admin", "password"), Map.entry("admin", "admin123"),
            Map.entry("admin", "12345678"), Map.entry("root", "root"), Map.entry("administrator", "password"),
            Map.entry("test", "test"), Map.entry("guest", "guest"));

    private final LoginFlowRunner login;

    public DefaultCredentialChecks(LoginFlowRunner login) {
        this.login = login;
    }

    public Result check(TestIdentity shape) {
        String checkId = "NET-07", title = "Default service credentials accepted";
        boolean sentAny = false;
        for (var cand : CANDIDATES) {
            TestIdentity probe = new TestIdentity(shape.getId(), shape.getTargetId(), shape.getLabel(), shape.getLoginUrl(),
                    shape.getUsernameField(), shape.getPasswordField(), cand.getKey(), "unused-enc", shape.getTokenPath(),
                    shape.getSessionType(), shape.getProbeUrl(), shape.getLogoutUrl(), shape.getLogoutMethod(), shape.getCreatedBy());
            var outcome = login.attempt(probe, cand.getValue());
            sentAny = true;
            if (outcome.success() && outcome.sessionCaptured()) {
                return new Result(checkId, title, Verdict.VULNERABLE, Severity.CRITICAL, shape.getLoginUrl(),
                        "The well-known credential pair \"" + cand.getKey() + "\" / \"" + cand.getValue()
                                + "\" was accepted and issued a session at " + shape.getLoginUrl() + ".",
                        "Remove or change every default account before go-live, and require a strong password on first login.");
            }
        }
        if (!sentAny) {
            return new Result(checkId, title, Verdict.NEEDS_MANUAL_REVIEW, Severity.INFORMATIONAL, shape.getLoginUrl(),
                    "No login attempt could be sent.", null);
        }
        return new Result(checkId, title, Verdict.NOT_VULNERABLE, Severity.INFORMATIONAL, shape.getLoginUrl(), null, null);
    }
}
