package com.sentinelops.service.logic;

import com.sentinelops.entity.SessionType;
import com.sentinelops.entity.TestIdentity;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Every verdict needs a working baseline first, then independent evidence from the tampered/repeated/parallel call. */
class BusinessLogicChecksTest {

    private static final String BODY = "{\"productId\":\"p1\",\"price\":99.99,\"quantity\":1}";

    private static TestIdentity identity() {
        return new TestIdentity("i1", "t1", "User A", "https://app.example.com/login", "email", "password",
                "u", "enc", "token", SessionType.HEADER_BEARER, null, null, "POST", "tess");
    }

    // ---------------- BIZ-01: tamper ----------------

    @Test
    void acceptingATamperedPriceIsVulnerable() throws Exception {
        BusinessHttpClient http = mock(BusinessHttpClient.class);
        when(http.send(any(), any(), contains("99.99"), any(), any())).thenReturn(new BusinessHttpClient.Result(200));
        when(http.send(any(), any(), contains("0.01"), any(), any())).thenReturn(new BusinessHttpClient.Result(201));

        var checks = new BusinessLogicChecks(mock(LoginFlowRunner.class), http);
        var results = checks.checkAll(null, null, "https://app.example.com/checkout", "POST", BODY, "price", "0.01", 5);

        var tamper = results.stream().filter(r -> r.checkId().equals("BIZ-01")).findFirst().orElseThrow();
        assertEquals(BusinessLogicChecks.Verdict.VULNERABLE, tamper.verdict());
    }

    @Test
    void rejectingATamperedPriceIsNotVulnerable() throws Exception {
        BusinessHttpClient http = mock(BusinessHttpClient.class);
        when(http.send(any(), any(), contains("99.99"), any(), any())).thenReturn(new BusinessHttpClient.Result(200));
        when(http.send(any(), any(), contains("0.01"), any(), any())).thenReturn(new BusinessHttpClient.Result(422));

        var checks = new BusinessLogicChecks(mock(LoginFlowRunner.class), http);
        var results = checks.checkAll(null, null, "https://app.example.com/checkout", "POST", BODY, "price", "0.01", 5);

        var tamper = results.stream().filter(r -> r.checkId().equals("BIZ-01")).findFirst().orElseThrow();
        assertEquals(BusinessLogicChecks.Verdict.NOT_VULNERABLE, tamper.verdict());
    }

    @Test
    void aFailingBaselineIsManualReviewNotAVerdict() throws Exception {
        BusinessHttpClient http = mock(BusinessHttpClient.class);
        when(http.send(any(), any(), any(), any(), any())).thenReturn(new BusinessHttpClient.Result(401));

        var checks = new BusinessLogicChecks(mock(LoginFlowRunner.class), http);
        var results = checks.checkAll(null, null, "https://app.example.com/checkout", "POST", BODY, "price", "0.01", 5);

        var tamper = results.stream().filter(r -> r.checkId().equals("BIZ-01")).findFirst().orElseThrow();
        assertEquals(BusinessLogicChecks.Verdict.NEEDS_MANUAL_REVIEW, tamper.verdict());
        // the tamper check's own baseline failed, so IT never sends a second (tampered) call - but BIZ-02 and
        // BIZ-03 still run independently and send their own requests, which also fail against this stub.
        var reuse = results.stream().filter(r -> r.checkId().equals("BIZ-02")).findFirst().orElseThrow();
        assertEquals(BusinessLogicChecks.Verdict.NEEDS_MANUAL_REVIEW, reuse.verdict());
    }

    @Test
    void noTamperFieldMeansNoTamperCheckAtAll() throws Exception {
        BusinessHttpClient http = mock(BusinessHttpClient.class);
        when(http.send(any(), any(), any(), any(), any())).thenReturn(new BusinessHttpClient.Result(409)); // reuse+race both "fail"

        var checks = new BusinessLogicChecks(mock(LoginFlowRunner.class), http);
        var results = checks.checkAll(null, null, "https://app.example.com/checkout", "POST", BODY, null, null, 2);

        assertTrue(results.stream().noneMatch(r -> r.checkId().equals("BIZ-01")));
        assertEquals(2, results.size()); // only BIZ-02 and BIZ-03
    }

    // ---------------- BIZ-02: reuse ----------------

    @Test
    void acceptingTheSameRequestTwiceIsVulnerable() throws Exception {
        BusinessHttpClient http = mock(BusinessHttpClient.class);
        when(http.send(any(), any(), any(), any(), any())).thenReturn(new BusinessHttpClient.Result(200));

        var checks = new BusinessLogicChecks(mock(LoginFlowRunner.class), http);
        var results = checks.checkAll(null, null, "https://app.example.com/apply-coupon", "POST", BODY, null, null, 2);

        var reuse = results.stream().filter(r -> r.checkId().equals("BIZ-02")).findFirst().orElseThrow();
        assertEquals(BusinessLogicChecks.Verdict.VULNERABLE, reuse.verdict());
    }

    @Test
    void rejectingTheSecondUseIsNotVulnerable() throws Exception {
        BusinessHttpClient http = mock(BusinessHttpClient.class);
        when(http.send(any(), any(), any(), any(), any())).thenReturn(new BusinessHttpClient.Result(200), new BusinessHttpClient.Result(409));

        var checks = new BusinessLogicChecks(mock(LoginFlowRunner.class), http);
        var results = checks.checkAll(null, null, "https://app.example.com/apply-coupon", "POST", BODY, null, null, 2);

        var reuse = results.stream().filter(r -> r.checkId().equals("BIZ-02")).findFirst().orElseThrow();
        assertEquals(BusinessLogicChecks.Verdict.NOT_VULNERABLE, reuse.verdict());
    }

    // ---------------- BIZ-03: race ----------------

    @Test
    void multipleConcurrentSuccessesIsVulnerable() throws Exception {
        BusinessHttpClient http = mock(BusinessHttpClient.class);
        when(http.send(any(), any(), any(), any(), any())).thenReturn(new BusinessHttpClient.Result(200));

        var checks = new BusinessLogicChecks(mock(LoginFlowRunner.class), http);
        var results = checks.checkAll(null, null, "https://app.example.com/redeem", "POST", BODY, null, null, 5);

        var race = results.stream().filter(r -> r.checkId().equals("BIZ-03")).findFirst().orElseThrow();
        assertEquals(BusinessLogicChecks.Verdict.VULNERABLE, race.verdict());
    }

    @Test
    void atMostOneConcurrentSuccessIsNotVulnerable() throws Exception {
        // Only the FIRST call ever made (the reuse check's baseline) succeeds; both reuse's second call and
        // every concurrent race call are refused - so the race check itself sees zero winners.
        AtomicInteger calls = new AtomicInteger();
        BusinessHttpClient http = mock(BusinessHttpClient.class);
        when(http.send(any(), any(), any(), any(), any())).thenAnswer(inv ->
                new BusinessHttpClient.Result(calls.getAndIncrement() == 0 ? 200 : 409));

        var checks = new BusinessLogicChecks(mock(LoginFlowRunner.class), http);
        var results = checks.checkAll(null, null, "https://app.example.com/redeem", "POST", BODY, null, null, 5);

        var race = results.stream().filter(r -> r.checkId().equals("BIZ-03")).findFirst().orElseThrow();
        assertEquals(BusinessLogicChecks.Verdict.NOT_VULNERABLE, race.verdict());
    }

    @Test
    void concurrencyIsClampedBetweenTwoAndTen() throws Exception {
        BusinessHttpClient http = mock(BusinessHttpClient.class);
        when(http.send(any(), any(), any(), any(), any())).thenReturn(new BusinessHttpClient.Result(409));

        var checks = new BusinessLogicChecks(mock(LoginFlowRunner.class), http);
        checks.checkAll(null, null, "https://app.example.com/redeem", "POST", BODY, null, null, 50);

        // reuse's own baseline is refused (409) so it never sends a second call; the race check always fires
        // the full (clamped-to-10) concurrency regardless of outcome.
        verify(http, times(10 + 1)).send(any(), any(), any(), any(), any());
    }

    // ---------------- auth / anonymous ----------------

    @Test
    void aFailedLoginIsManualReviewForEveryCheckAndSendsNothing() throws Exception {
        LoginFlowRunner login = mock(LoginFlowRunner.class);
        when(login.attempt(any(), any())).thenReturn(new LoginFlowRunner.LoginOutcome(false, 401, false, null, "bad creds"));
        BusinessHttpClient http = mock(BusinessHttpClient.class);

        var checks = new BusinessLogicChecks(login, http);
        var results = checks.checkAll(identity(), "pw", "https://app.example.com/checkout", "POST", BODY, "price", "0.01", 5);

        assertEquals(3, results.size());
        assertTrue(results.stream().allMatch(r -> r.verdict() == BusinessLogicChecks.Verdict.NEEDS_MANUAL_REVIEW));
        verifyNoInteractions(http);
    }

    @Test
    void anAnonymousProbeNeverLogsIn() throws Exception {
        LoginFlowRunner login = mock(LoginFlowRunner.class);
        BusinessHttpClient http = mock(BusinessHttpClient.class);
        when(http.send(any(), any(), any(), isNull(), isNull())).thenReturn(new BusinessHttpClient.Result(200));

        var checks = new BusinessLogicChecks(login, http);
        checks.checkAll(null, null, "https://app.example.com/checkout", "POST", BODY, null, null, 2);

        verifyNoInteractions(login);
    }
}
