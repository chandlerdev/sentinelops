package com.sentinelops.service.logic;

import com.sentinelops.entity.SessionType;
import com.sentinelops.entity.TestIdentity;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Every verdict needs both baselines (each identity reading their OWN resource) before any cross-check counts. */
class IdorChecksTest {

    private static TestIdentity identity(String id, String label) {
        return new TestIdentity(id, "t1", label, "https://app.example.com/login", "email", "password",
                "u-" + id, "enc", "token", SessionType.HEADER_BEARER, null, null, "POST", "tess");
    }

    private static LoginFlowRunner loginFor(String tokenA, String tokenB) throws Exception {
        LoginHttpClient http = mock(LoginHttpClient.class);
        when(http.post(any(), contains("u-a"))).thenReturn(new LoginHttpClient.Response(200, Map.of(), "{\"token\":\"" + tokenA + "\"}"));
        when(http.post(any(), contains("u-b"))).thenReturn(new LoginHttpClient.Response(200, Map.of(), "{\"token\":\"" + tokenB + "\"}"));
        return new LoginFlowRunner(http);
    }

    @Test
    void bAccessingAsResourceIsVulnerable() throws Exception {
        TestIdentity a = identity("a", "User A"), b = identity("b", "User B");
        ProbeHttpClient probe = mock(ProbeHttpClient.class);
        when(probe.callWithBody(eq("GET"), eq("https://app.example.com/api/orders/101"), eq("Authorization"), eq("Bearer tok-a")))
                .thenReturn(new ProbeHttpClient.Result(200, 50)); // A reading A's own order
        when(probe.callWithBody(eq("GET"), eq("https://app.example.com/api/orders/102"), eq("Authorization"), eq("Bearer tok-b")))
                .thenReturn(new ProbeHttpClient.Result(200, 50)); // B reading B's own order
        when(probe.callWithBody(eq("GET"), eq("https://app.example.com/api/orders/101"), eq("Authorization"), eq("Bearer tok-b")))
                .thenReturn(new ProbeHttpClient.Result(200, 50)); // B reading A's order -> should not be allowed
        when(probe.callWithBody(eq("GET"), eq("https://app.example.com/api/orders/102"), eq("Authorization"), eq("Bearer tok-a")))
                .thenReturn(new ProbeHttpClient.Result(403, 10)); // A reading B's order -> correctly rejected

        var checks = new IdorChecks(loginFor("tok-a", "tok-b"), probe);
        var results = checks.checkCrossAccess(a, "pw", "101", b, "pw", "102", "https://app.example.com/api/orders/{id}");

        assertEquals(2, results.size());
        var bToA = results.stream().filter(r -> r.checkId().equals("ACC-01a")).findFirst().orElseThrow();
        assertEquals(IdorChecks.Verdict.VULNERABLE, bToA.verdict());
        assertTrue(bToA.location().contains("101"));
    }

    @Test
    void aCannotAccessBsResourceIsNotVulnerable() throws Exception {
        TestIdentity a = identity("a", "User A"), b = identity("b", "User B");
        ProbeHttpClient probe = mock(ProbeHttpClient.class);
        when(probe.callWithBody(eq("GET"), contains("101"), any(), eq("Bearer tok-a"))).thenReturn(new ProbeHttpClient.Result(200, 50));
        when(probe.callWithBody(eq("GET"), contains("102"), any(), eq("Bearer tok-b"))).thenReturn(new ProbeHttpClient.Result(200, 50));
        when(probe.callWithBody(eq("GET"), contains("102"), any(), eq("Bearer tok-a"))).thenReturn(new ProbeHttpClient.Result(403, 10));
        when(probe.callWithBody(eq("GET"), contains("101"), any(), eq("Bearer tok-b"))).thenReturn(new ProbeHttpClient.Result(403, 10));

        var checks = new IdorChecks(loginFor("tok-a", "tok-b"), probe);
        var results = checks.checkCrossAccess(a, "pw", "101", b, "pw", "102", "https://app.example.com/api/orders/{id}");

        assertTrue(results.stream().allMatch(r -> r.verdict() == IdorChecks.Verdict.NOT_VULNERABLE));
    }

    @Test
    void anAcceptedButEmptyCrossResponseIsManualReviewNotAFalsePositive() throws Exception {
        TestIdentity a = identity("a", "User A"), b = identity("b", "User B");
        ProbeHttpClient probe = mock(ProbeHttpClient.class);
        when(probe.callWithBody(eq("GET"), contains("101"), any(), eq("Bearer tok-a"))).thenReturn(new ProbeHttpClient.Result(200, 50));
        when(probe.callWithBody(eq("GET"), contains("102"), any(), eq("Bearer tok-b"))).thenReturn(new ProbeHttpClient.Result(200, 50));
        // B "succeeds" against A's resource, but with an empty body - likely a generic 200, not real data
        when(probe.callWithBody(eq("GET"), contains("101"), any(), eq("Bearer tok-b"))).thenReturn(new ProbeHttpClient.Result(200, 0));
        when(probe.callWithBody(eq("GET"), contains("102"), any(), eq("Bearer tok-a"))).thenReturn(new ProbeHttpClient.Result(403, 10));

        var checks = new IdorChecks(loginFor("tok-a", "tok-b"), probe);
        var results = checks.checkCrossAccess(a, "pw", "101", b, "pw", "102", "https://app.example.com/api/orders/{id}");

        var bToA = results.stream().filter(r -> r.checkId().equals("ACC-01a")).findFirst().orElseThrow();
        assertEquals(IdorChecks.Verdict.NEEDS_MANUAL_REVIEW, bToA.verdict());
    }

    @Test
    void cannotEstablishBaselineNeedsManualReviewForBoth() throws Exception {
        TestIdentity a = identity("a", "User A"), b = identity("b", "User B");
        ProbeHttpClient probe = mock(ProbeHttpClient.class);
        // A cannot even read their own resource - the probe/id/identity is misconfigured
        when(probe.callWithBody(eq("GET"), contains("101"), any(), eq("Bearer tok-a"))).thenReturn(new ProbeHttpClient.Result(404, 0));
        when(probe.callWithBody(eq("GET"), contains("102"), any(), eq("Bearer tok-b"))).thenReturn(new ProbeHttpClient.Result(200, 50));

        var checks = new IdorChecks(loginFor("tok-a", "tok-b"), probe);
        var results = checks.checkCrossAccess(a, "pw", "101", b, "pw", "102", "https://app.example.com/api/orders/{id}");

        assertTrue(results.stream().anyMatch(r -> r.verdict() == IdorChecks.Verdict.NEEDS_MANUAL_REVIEW));
        verify(probe, never()).callWithBody(eq("GET"), contains("101"), any(), eq("Bearer tok-b")); // never attempts the cross-check
    }

    @Test
    void aFailedLoginIsManualReviewNotAVerdict() {
        TestIdentity a = identity("a", "User A"), b = identity("b", "User B");
        LoginFlowRunner login = mock(LoginFlowRunner.class);
        when(login.attempt(eq(a), any())).thenReturn(new LoginFlowRunner.LoginOutcome(false, 401, false, null, "bad creds"));
        var checks = new IdorChecks(login, mock(ProbeHttpClient.class));
        var results = checks.checkCrossAccess(a, "pw", "101", b, "pw", "102", "https://app.example.com/api/orders/{id}");

        assertEquals(2, results.size());
        assertTrue(results.stream().allMatch(r -> r.verdict() == IdorChecks.Verdict.NEEDS_MANUAL_REVIEW));
        verify(login, never()).attempt(eq(b), any());
    }
}
