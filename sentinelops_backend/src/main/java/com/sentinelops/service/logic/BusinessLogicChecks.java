package com.sentinelops.service.logic;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sentinelops.entity.Severity;
import com.sentinelops.entity.SessionType;
import com.sentinelops.entity.TestIdentity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

/**
 * Phase 4 of the logic-testing engine (E/J: checkout / business logic; see PENTEST_COVERAGE_PLAN.md).
 * Generalizes several checklist items into one reusable probe, since every target's checkout/coupon API is
 * different: BIZ-01 (parameter tamper accepted — covers ECOM-02/03/04 price/quantity/discount), BIZ-02
 * (identical request accepted twice — covers ECOM-05/09 coupon reuse / duplicate orders) and BIZ-03 (N
 * concurrent identical requests all accepted — covers BUS-07 race conditions).
 *
 * Every verdict is read off the HTTP status of real requests, never guessed: a tampered/duplicate/parallel
 * request is only VULNERABLE when it is independently accepted (2xx) right after a working baseline call.
 * Each check sends its own baseline+test pair, but because these are real stateful actions (an order, a
 * coupon use), one check CAN consume state the next one relies on (e.g. a single-use coupon) — run probes
 * one at a time against a resettable test account when that matters.
 */
@Component
public class BusinessLogicChecks {

    public enum Verdict { VULNERABLE, NOT_VULNERABLE, NEEDS_MANUAL_REVIEW }

    public record Result(String checkId, String title, Verdict verdict, Severity severity, String location,
                         String description, String remediation) {
        static Result review(String checkId, String title, String location, String why) {
            return new Result(checkId, title, Verdict.NEEDS_MANUAL_REVIEW, Severity.INFORMATIONAL, location, why, null);
        }
        static Result clean(String checkId, String title, String location) {
            return new Result(checkId, title, Verdict.NOT_VULNERABLE, Severity.INFORMATIONAL, location, null, null);
        }
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    private final LoginFlowRunner login;
    private final BusinessHttpClient http;

    public BusinessLogicChecks(LoginFlowRunner login, BusinessHttpClient http) {
        this.login = login;
        this.http = http;
    }

    private String headerName(TestIdentity i) { return i.getSessionType() == SessionType.COOKIE ? "Cookie" : "Authorization"; }

    private String headerValue(TestIdentity i, String sessionValue) {
        if (i.getSessionType() == SessionType.COOKIE) {
            int semi = sessionValue.indexOf(';');
            return semi > 0 ? sessionValue.substring(0, semi) : sessionValue;
        }
        return "Bearer " + sessionValue;
    }

    private boolean ok(int status) { return status >= 200 && status < 300; }

    public List<Result> checkAll(TestIdentity identity, String password, String requestUrl, String method,
                                 String bodyTemplate, String tamperedField, String tamperedValue, int concurrency) {
        List<Result> out = new ArrayList<>();
        String tamperId = "BIZ-01", tamperTitle = "Tampered parameter accepted (price / quantity / discount)";
        String reuseId = "BIZ-02", reuseTitle = "Identical request accepted twice (coupon reuse / duplicate order)";
        String raceId = "BIZ-03", raceTitle = "Concurrent identical requests all accepted (race condition)";

        String hName = null, hVal = null;
        if (identity != null) {
            var outcome = login.attempt(identity, password);
            if (!outcome.success() || !outcome.sessionCaptured()) {
                String why = "Could not log in as " + identity.getLabel() + ": " + outcome.detail();
                out.add(Result.review(tamperId, tamperTitle, requestUrl, why));
                out.add(Result.review(reuseId, reuseTitle, requestUrl, why));
                out.add(Result.review(raceId, raceTitle, requestUrl, why));
                return out;
            }
            hName = headerName(identity);
            hVal = headerValue(identity, outcome.sessionValue());
        }

        if (tamperedField != null && !tamperedField.isBlank()) {
            out.add(checkTamper(tamperId, tamperTitle, requestUrl, method, bodyTemplate, tamperedField, tamperedValue, hName, hVal));
        }
        out.add(checkReuse(reuseId, reuseTitle, requestUrl, method, bodyTemplate, hName, hVal));
        out.add(checkRace(raceId, raceTitle, requestUrl, method, bodyTemplate, hName, hVal, Math.max(2, Math.min(concurrency, 10))));
        return out;
    }

    private Result checkTamper(String checkId, String title, String url, String method, String bodyTemplate,
                               String tamperedField, String tamperedValue, String hName, String hVal) {
        BusinessHttpClient.Result baseline;
        try {
            baseline = http.send(method, url, bodyTemplate, hName, hVal);
        } catch (Exception ex) {
            return Result.review(checkId, title, url, "The baseline request could not be sent: " + ex.getClass().getSimpleName());
        }
        if (!ok(baseline.status())) {
            return Result.review(checkId, title, url, "The baseline request itself was not accepted (status "
                    + baseline.status() + "); check the body template, URL or identity.");
        }

        String tamperedBody;
        try {
            ObjectNode node = (ObjectNode) JSON.readTree(bodyTemplate);
            JsonNode value = JSON.readTree(tamperedValue);
            node.set(tamperedField, value);
            tamperedBody = node.toString();
        } catch (Exception ex) {
            return Result.review(checkId, title, url, "Could not build the tampered request body: " + ex.getClass().getSimpleName());
        }

        BusinessHttpClient.Result tampered;
        try {
            tampered = http.send(method, url, tamperedBody, hName, hVal);
        } catch (Exception ex) {
            return Result.review(checkId, title, url, "The tampered request could not be sent: " + ex.getClass().getSimpleName());
        }
        if (ok(tampered.status())) {
            return new Result(checkId, title, Verdict.VULNERABLE, Severity.HIGH, url,
                    "The server accepted a client-supplied \"" + tamperedField + "\": " + tamperedValue
                            + " (status " + tampered.status() + ") straight after a normal request succeeded.",
                    "Recompute price, quantity limits, discounts and totals server-side from trusted data (the "
                            + "catalog, stock, coupon rules) - never trust a value the client sends for them.");
        }
        return Result.clean(checkId, title, url);
    }

    private Result checkReuse(String checkId, String title, String url, String method, String bodyTemplate,
                              String hName, String hVal) {
        BusinessHttpClient.Result first;
        try {
            first = http.send(method, url, bodyTemplate, hName, hVal);
        } catch (Exception ex) {
            return Result.review(checkId, title, url, "The first request could not be sent: " + ex.getClass().getSimpleName());
        }
        if (!ok(first.status())) {
            return Result.review(checkId, title, url, "The request was not accepted the first time (status "
                    + first.status() + "); cannot test reuse.");
        }
        BusinessHttpClient.Result second;
        try {
            second = http.send(method, url, bodyTemplate, hName, hVal);
        } catch (Exception ex) {
            return Result.review(checkId, title, url, "The repeat request could not be sent: " + ex.getClass().getSimpleName());
        }
        if (ok(second.status())) {
            return new Result(checkId, title, Verdict.VULNERABLE, Severity.MEDIUM, url,
                    "The exact same request was accepted twice in a row (status " + second.status()
                            + " both times). A single-use action (coupon, limited-stock purchase, one-time order) does not appear to be enforced.",
                    "Make the action idempotent or single-use server-side: check and consume a coupon/stock/ticket "
                            + "atomically, and reject a repeat of the same operation.");
        }
        return Result.clean(checkId, title, url);
    }

    private Result checkRace(String checkId, String title, String url, String method, String bodyTemplate,
                             String hName, String hVal, int concurrency) {
        ExecutorService pool = Executors.newFixedThreadPool(concurrency);
        try {
            List<Callable<Integer>> tasks = new ArrayList<>();
            for (int i = 0; i < concurrency; i++) {
                tasks.add(() -> {
                    try {
                        return http.send(method, url, bodyTemplate, hName, hVal).status();
                    } catch (Exception ex) {
                        return -1;
                    }
                });
            }
            List<Future<Integer>> futures = pool.invokeAll(tasks, 30, TimeUnit.SECONDS);
            int succeeded = 0, sent = 0;
            for (Future<Integer> f : futures) {
                try {
                    int status = f.get();
                    if (status == -1) continue;
                    sent++;
                    if (ok(status)) succeeded++;
                } catch (Exception ignored) { /* counted as not sent */ }
            }
            if (sent == 0) {
                return Result.review(checkId, title, url, "None of the " + concurrency + " concurrent requests could be sent.");
            }
            if (succeeded > 1) {
                return new Result(checkId, title, Verdict.VULNERABLE, Severity.HIGH, url,
                        succeeded + " of " + sent + " concurrent identical requests all succeeded. A limited action "
                                + "(stock, a single coupon use, a balance deduction) should allow only one to win.",
                        "Serialize the operation with a database-level lock, a unique constraint, or an atomic "
                                + "check-and-decrement, so concurrent requests cannot all succeed.");
            }
            return Result.clean(checkId, title, url);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return Result.review(checkId, title, url, "The concurrency check was interrupted.");
        } finally {
            pool.shutdownNow();
        }
    }
}
