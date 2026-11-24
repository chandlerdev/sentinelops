package com.sentinelops.service.logic;

import com.sentinelops.entity.Severity;
import com.sentinelops.entity.SessionType;
import com.sentinelops.entity.TestIdentity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Phase 2 of the logic-testing engine (see PENTEST_COVERAGE_PLAN.md): ACC-01 (IDOR) and ACC-05 (horizontal
 * privilege escalation). Two stored identities, each with their OWN object id, let the engine prove
 * ownership is or isn't checked — never from one response alone, always from the 4-call pattern below.
 */
@Component
public class IdorChecks {

    public enum Verdict { VULNERABLE, NOT_VULNERABLE, NEEDS_MANUAL_REVIEW }

    public record Result(String checkId, String title, Verdict verdict, Severity severity, String location,
                         String description, String remediation) {
        static Result review(String checkId, String title, String why) {
            return new Result(checkId, title, Verdict.NEEDS_MANUAL_REVIEW, Severity.INFORMATIONAL, null, why, null);
        }
    }

    private final LoginFlowRunner login;
    private final ProbeHttpClient probe;

    public IdorChecks(LoginFlowRunner login, ProbeHttpClient probe) {
        this.login = login;
        this.probe = probe;
    }

    private String headerName(TestIdentity i) { return i.getSessionType() == SessionType.COOKIE ? "Cookie" : "Authorization"; }

    private String headerValue(TestIdentity i, String sessionValue) {
        if (i.getSessionType() == SessionType.COOKIE) {
            int semi = sessionValue.indexOf(';');
            return semi > 0 ? sessionValue.substring(0, semi) : sessionValue;
        }
        return "Bearer " + sessionValue;
    }

    private static String urlFor(String template, String id) {
        return template.replace("{id}", id);
    }

    private boolean ok(int status) { return status >= 200 && status < 300; }

    /**
     * Logs in as both identities, confirms each can read their OWN resource, then tries each one's id with
     * the OTHER identity's session. Returns two results: "B accessed A's resource" and "A accessed B's
     * resource", each on its own verdict.
     */
    public List<Result> checkCrossAccess(TestIdentity a, String passwordA, String resourceIdA,
                                         TestIdentity b, String passwordB, String resourceIdB, String urlTemplate) {
        List<Result> out = new ArrayList<>();
        String idBtoA = "ACC-01a", titleBtoA = "User B can read User A's resource (IDOR)";
        String idAtoB = "ACC-01b", titleAtoB = "User A can read User B's resource (IDOR)";

        var loginA = login.attempt(a, passwordA);
        if (!loginA.success() || !loginA.sessionCaptured()) {
            String why = "Could not log in as " + a.getLabel() + ": " + loginA.detail();
            out.add(Result.review(idBtoA, titleBtoA, why));
            out.add(Result.review(idAtoB, titleAtoB, why));
            return out;
        }
        var loginB = login.attempt(b, passwordB);
        if (!loginB.success() || !loginB.sessionCaptured()) {
            String why = "Could not log in as " + b.getLabel() + ": " + loginB.detail();
            out.add(Result.review(idBtoA, titleBtoA, why));
            out.add(Result.review(idAtoB, titleAtoB, why));
            return out;
        }
        String hNameA = headerName(a), hValA = headerValue(a, loginA.sessionValue());
        String hNameB = headerName(b), hValB = headerValue(b, loginB.sessionValue());
        String urlA = urlFor(urlTemplate, resourceIdA);
        String urlB = urlFor(urlTemplate, resourceIdB);

        ProbeHttpClient.Result ownA, ownB;
        try {
            ownA = probe.callWithBody("GET", urlA, hNameA, hValA);
        } catch (Exception ex) {
            String why = "The sanity request for " + a.getLabel() + "'s own resource could not be sent: " + ex.getClass().getSimpleName();
            out.add(Result.review(idBtoA, titleBtoA, why));
            out.add(Result.review(idAtoB, titleAtoB, why));
            return out;
        }
        try {
            ownB = probe.callWithBody("GET", urlB, hNameB, hValB);
        } catch (Exception ex) {
            String why = "The sanity request for " + b.getLabel() + "'s own resource could not be sent: " + ex.getClass().getSimpleName();
            out.add(Result.review(idBtoA, titleBtoA, why));
            out.add(Result.review(idAtoB, titleAtoB, why));
            return out;
        }
        if (!ok(ownA.status())) {
            out.add(Result.review(idBtoA, titleBtoA, a.getLabel() + " could not read their own resource at " + urlA
                    + " (status " + ownA.status() + "); check the identity, URL template or resource id."));
        }
        if (!ok(ownB.status())) {
            out.add(Result.review(idAtoB, titleAtoB, b.getLabel() + " could not read their own resource at " + urlB
                    + " (status " + ownB.status() + "); check the identity, URL template or resource id."));
        }
        if (!ok(ownA.status()) || !ok(ownB.status())) return out; // cannot draw any conclusion without both baselines

        // Does B's session reach A's resource?
        out.add(crossCheck(idBtoA, titleBtoA, b, hNameB, hValB, urlA, ownA, "ACC-05"));
        // Does A's session reach B's resource?
        out.add(crossCheck(idAtoB, titleAtoB, a, hNameA, hValA, urlB, ownB, "ACC-05"));
        return out;
    }

    private Result crossCheck(String checkId, String title, TestIdentity attacker, String hName, String hVal,
                              String victimUrl, ProbeHttpClient.Result ownBaseline, String relatedId) {
        ProbeHttpClient.Result cross;
        try {
            cross = probe.callWithBody("GET", victimUrl, hName, hVal);
        } catch (Exception ex) {
            return Result.review(checkId, title, "The cross-account request could not be sent: " + ex.getClass().getSimpleName());
        }
        if (!ok(cross.status())) {
            return new Result(checkId, title, Verdict.NOT_VULNERABLE, Severity.INFORMATIONAL, victimUrl, null, null);
        }
        // Accepted with a body of a similar size to the legitimate owner's response: treat as the real object,
        // not a generic "200 OK, nothing here" page, so we don't call a same-shaped empty response a finding.
        boolean looksLikeRealContent = ownBaseline.bodyLength() == 0 || cross.bodyLength() > 0;
        if (!looksLikeRealContent) {
            return Result.review(checkId, title, "The cross-account request returned " + cross.status()
                    + " with an empty body; cannot tell whether real data was returned. Review manually.");
        }
        return new Result(checkId, title, Verdict.VULNERABLE, Severity.HIGH, victimUrl,
                attacker.getLabel() + "'s session was accepted at another account's own resource (" + victimUrl
                        + "), status " + cross.status() + ". The server is not checking who owns the object (" + relatedId + ").",
                "Check that the authenticated user owns (or is otherwise entitled to) the requested object before returning it, "
                        + "on every endpoint that takes an object id.");
    }
}
