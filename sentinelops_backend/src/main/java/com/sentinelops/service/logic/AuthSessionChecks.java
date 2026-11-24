package com.sentinelops.service.logic;

import com.sentinelops.entity.SessionType;
import com.sentinelops.entity.Severity;
import com.sentinelops.entity.TestIdentity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Phase 1 of the logic-testing engine (see PENTEST_COVERAGE_PLAN.md): AUTH-11 (JWT manipulation) and
 * AUTH-12 (logout does not end the session). Every check reports one of three verdicts — it never calls
 * something VULNERABLE from a single unusual response, only from evidence that the "before" state worked
 * and the "after"/tampered state should not have.
 */
@Component
public class AuthSessionChecks {

    public enum Verdict { VULNERABLE, NOT_VULNERABLE, NEEDS_MANUAL_REVIEW }

    public record Result(String checkId, String title, Verdict verdict, Severity severity, String location,
                         String description, String remediation) {
        static Result review(String checkId, String title, String why) {
            return new Result(checkId, title, Verdict.NEEDS_MANUAL_REVIEW, Severity.INFORMATIONAL, null, why, null);
        }
        static Result clean(String checkId, String title, String location) {
            return new Result(checkId, title, Verdict.NOT_VULNERABLE, Severity.INFORMATIONAL, location, null, null);
        }
    }

    private final LoginFlowRunner login;
    private final ProbeHttpClient probe;

    public AuthSessionChecks(LoginFlowRunner login, ProbeHttpClient probe) {
        this.login = login;
        this.probe = probe;
    }

    private String headerName(TestIdentity i) { return i.getSessionType() == SessionType.COOKIE ? "Cookie" : "Authorization"; }

    private String headerValue(TestIdentity i, String sessionValue) {
        if (i.getSessionType() == SessionType.COOKIE) {
            int semi = sessionValue.indexOf(';');
            return semi > 0 ? sessionValue.substring(0, semi) : sessionValue; // "name=value" only
        }
        return "Bearer " + sessionValue;
    }

    private boolean ok(int status) { return status >= 200 && status < 300; }

    /** AUTH-12: does the session still work after logout? */
    public Result checkLogoutSessionReuse(TestIdentity identity, String password) {
        final String id = "AUTH-12";
        final String title = "Session usable after logout";
        if (identity.getProbeUrl() == null || identity.getProbeUrl().isBlank()) {
            return Result.review(id, title, "No probe endpoint is configured for this identity; cannot tell whether the session is still authenticated.");
        }
        if (identity.getLogoutUrl() == null || identity.getLogoutUrl().isBlank()) {
            return Result.review(id, title, "No logout endpoint is configured for this identity.");
        }
        var loginOutcome = login.attempt(identity, password);
        if (!loginOutcome.success() || !loginOutcome.sessionCaptured()) {
            return Result.review(id, title, "Login did not succeed or no session was captured: " + loginOutcome.detail());
        }
        String hName = headerName(identity), hVal = headerValue(identity, loginOutcome.sessionValue());

        int before;
        try {
            before = probe.call("GET", identity.getProbeUrl(), hName, hVal);
        } catch (Exception ex) {
            return Result.review(id, title, "The probe request before logout could not be sent: " + ex.getClass().getSimpleName());
        }
        if (!ok(before)) {
            return Result.review(id, title, "The session did not look authenticated before logout (probe returned " + before
                    + "). The probe endpoint or field names may be misconfigured.");
        }

        try {
            probe.call(identity.getLogoutMethod(), identity.getLogoutUrl(), hName, hVal);
        } catch (Exception ex) {
            return Result.review(id, title, "The logout request could not be sent: " + ex.getClass().getSimpleName());
        }

        int after;
        try {
            after = probe.call("GET", identity.getProbeUrl(), hName, hVal);
        } catch (Exception ex) {
            return Result.review(id, title, "The probe request after logout could not be sent: " + ex.getClass().getSimpleName());
        }
        if (ok(after)) {
            return new Result(id, title, Verdict.VULNERABLE, Severity.HIGH, identity.getProbeUrl(),
                    "The same session (" + identity.getSessionType() + ") still authenticated a request after calling "
                            + identity.getLogoutUrl() + " (probe returned " + before + " before logout and " + after + " after).",
                    "Invalidate the session (and any related token) server-side on logout, not only on the client.");
        }
        return Result.clean(id, title, identity.getProbeUrl());
    }

    /** AUTH-11: alg=none and a tampered privilege claim with the original signature left untouched. */
    public List<Result> checkJwt(TestIdentity identity, String password) {
        List<Result> out = new ArrayList<>();
        String algId = "AUTH-11a", algTitle = "JWT accepted with alg=none";
        String claimId = "AUTH-11b", claimTitle = "JWT signature not validated";

        if (identity.getSessionType() != SessionType.HEADER_BEARER) {
            out.add(Result.review(algId, algTitle, "This identity uses a cookie session, not a bearer token; JWT checks do not apply."));
            return out;
        }
        if (identity.getProbeUrl() == null || identity.getProbeUrl().isBlank()) {
            out.add(Result.review(algId, algTitle, "No probe endpoint is configured for this identity."));
            return out;
        }
        var loginOutcome = login.attempt(identity, password);
        if (!loginOutcome.success() || !loginOutcome.sessionCaptured()) {
            out.add(Result.review(algId, algTitle, "Login did not succeed or no session was captured: " + loginOutcome.detail()));
            return out;
        }
        String token = loginOutcome.sessionValue();
        if (!JwtTool.looksLikeJwt(token)) {
            out.add(Result.review(algId, algTitle, "The captured token is not a JWT (3-part, alg header); manual review needed for this session format."));
            return out;
        }

        int sane;
        try {
            sane = probe.call("GET", identity.getProbeUrl(), "Authorization", "Bearer " + token);
        } catch (Exception ex) {
            out.add(Result.review(algId, algTitle, "The sanity probe with the real token could not be sent: " + ex.getClass().getSimpleName()));
            return out;
        }
        if (!ok(sane)) {
            out.add(Result.review(algId, algTitle, "The real token did not look authenticated at the probe endpoint (" + sane + "); cannot continue."));
            return out;
        }

        // alg=none
        try {
            String forged = JwtTool.toAlgNone(token);
            int status = probe.call("GET", identity.getProbeUrl(), "Authorization", "Bearer " + forged);
            out.add(ok(status)
                    ? new Result(algId, algTitle, Verdict.VULNERABLE, Severity.CRITICAL, identity.getProbeUrl(),
                        "A token rewritten with \"alg\":\"none\" and no signature was accepted (probe returned " + status + ").",
                        "Reject tokens whose algorithm is \"none\" and verify the signature with a server-held key on every request.")
                    : Result.clean(algId, algTitle, identity.getProbeUrl()));
        } catch (Exception ex) {
            out.add(Result.review(algId, algTitle, "The alg=none probe could not be sent: " + ex.getClass().getSimpleName()));
        }

        // claim tamper, original signature left as-is
        var tampered = JwtTool.tamperPrivilegeClaim(token);
        if (tampered == null) {
            out.add(Result.review(claimId, claimTitle, "No recognisable privilege claim (role/isAdmin/scope/...) was found to tamper."));
        } else {
            try {
                int status = probe.call("GET", identity.getProbeUrl(), "Authorization", "Bearer " + tampered.token());
                out.add(ok(status)
                        ? new Result(claimId, claimTitle, Verdict.VULNERABLE, Severity.CRITICAL, identity.getProbeUrl(),
                            "The \"" + tampered.claimChanged() + "\" claim was changed without re-signing the token, and it was still "
                                    + "accepted (probe returned " + status + "). The server is not validating the JWT signature.",
                            "Verify the JWT signature on every request before trusting any claim in it.")
                        : Result.clean(claimId, claimTitle, identity.getProbeUrl()));
            } catch (Exception ex) {
                out.add(Result.review(claimId, claimTitle, "The tampered-claim probe could not be sent: " + ex.getClass().getSimpleName()));
            }
        }
        return out;
    }
}
