package com.sentinelops.service.logic;

import com.sentinelops.entity.SessionType;
import com.sentinelops.entity.TestIdentity;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Every verdict must come from two observed states (before/after, real/forged), never from one odd response. */
class AuthSessionChecksTest {

    private static String b64(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static String jwtWithClaim(String claimJson) {
        return b64("{\"alg\":\"HS256\"}") + "." + b64("{\"sub\":\"u1\"," + claimJson + "}") + ".sig";
    }

    private static TestIdentity bearerIdentity(String probeUrl, String logoutUrl) {
        return new TestIdentity("i1", "t1", "User A", "https://app.example.com/login", "email", "password",
                "u", "enc", "token", SessionType.HEADER_BEARER, probeUrl, logoutUrl, "POST", "tess");
    }

    private static TestIdentity cookieIdentity(String probeUrl, String logoutUrl) {
        return new TestIdentity("i1", "t1", "User A", "https://app.example.com/login", "email", "password",
                "u", "enc", null, SessionType.COOKIE, probeUrl, logoutUrl, "POST", "tess");
    }

    // ---------------- AUTH-12: logout session reuse ----------------

    @Test
    void sessionStillWorkingAfterLogoutIsVulnerable() throws Exception {
        LoginHttpClient http = mock(LoginHttpClient.class);
        when(http.post(any(), any())).thenReturn(new LoginHttpClient.Response(200, Map.of(), "{\"token\":\"abc\"}"));
        ProbeHttpClient probe = mock(ProbeHttpClient.class);
        when(probe.call(eq("GET"), eq("https://app.example.com/me"), eq("Authorization"), eq("Bearer abc"))).thenReturn(200, 200);
        when(probe.call(eq("POST"), eq("https://app.example.com/logout"), eq("Authorization"), eq("Bearer abc"))).thenReturn(204);

        var checks = new AuthSessionChecks(new LoginFlowRunner(http), probe);
        var result = checks.checkLogoutSessionReuse(
                bearerIdentity("https://app.example.com/me", "https://app.example.com/logout"), "pw");

        assertEquals(AuthSessionChecks.Verdict.VULNERABLE, result.verdict());
        assertEquals("AUTH-12", result.checkId());
    }

    @Test
    void sessionRejectedAfterLogoutIsNotVulnerable() throws Exception {
        LoginHttpClient http = mock(LoginHttpClient.class);
        when(http.post(any(), any())).thenReturn(new LoginHttpClient.Response(200, Map.of(), "{\"token\":\"abc\"}"));
        ProbeHttpClient probe = mock(ProbeHttpClient.class);
        when(probe.call(eq("GET"), any(), any(), any())).thenReturn(200, 401); // before=200, after=401
        when(probe.call(eq("POST"), any(), any(), any())).thenReturn(204);

        var checks = new AuthSessionChecks(new LoginFlowRunner(http), probe);
        var result = checks.checkLogoutSessionReuse(
                bearerIdentity("https://app.example.com/me", "https://app.example.com/logout"), "pw");

        assertEquals(AuthSessionChecks.Verdict.NOT_VULNERABLE, result.verdict());
    }

    @Test
    void missingProbeOrLogoutUrlNeedsManualReviewNotAVerdict() {
        var checks = new AuthSessionChecks(mock(LoginFlowRunner.class), mock(ProbeHttpClient.class));
        assertEquals(AuthSessionChecks.Verdict.NEEDS_MANUAL_REVIEW,
                checks.checkLogoutSessionReuse(bearerIdentity(null, "https://app.example.com/logout"), "pw").verdict());
        assertEquals(AuthSessionChecks.Verdict.NEEDS_MANUAL_REVIEW,
                checks.checkLogoutSessionReuse(bearerIdentity("https://app.example.com/me", null), "pw").verdict());
    }

    @Test
    void aFailedLoginNeedsManualReviewNotAVerdict() {
        LoginFlowRunner runner = mock(LoginFlowRunner.class);
        when(runner.attempt(any(), any())).thenReturn(new LoginFlowRunner.LoginOutcome(false, 401, false, null, "bad creds"));
        var checks = new AuthSessionChecks(runner, mock(ProbeHttpClient.class));
        var result = checks.checkLogoutSessionReuse(bearerIdentity("https://app.example.com/me", "https://app.example.com/logout"), "pw");
        assertEquals(AuthSessionChecks.Verdict.NEEDS_MANUAL_REVIEW, result.verdict());
    }

    @Test
    void cookieSessionsUseTheCookieHeaderNotAuthorization() throws Exception {
        LoginHttpClient http = mock(LoginHttpClient.class);
        when(http.post(any(), any())).thenReturn(new LoginHttpClient.Response(200,
                Map.of("set-cookie", java.util.List.of("session=xyz; HttpOnly; Path=/")), "{}"));
        ProbeHttpClient probe = mock(ProbeHttpClient.class);
        when(probe.call(eq("GET"), any(), eq("Cookie"), eq("session=xyz"))).thenReturn(401); // correctly rejected
        when(probe.call(eq("POST"), any(), any(), any())).thenReturn(204);

        var checks = new AuthSessionChecks(new LoginFlowRunner(http), probe);
        var result = checks.checkLogoutSessionReuse(
                cookieIdentity("https://app.example.com/me", "https://app.example.com/logout"), "pw");
        // before-logout probe already fails -> manual review, proves the Cookie header (not Authorization) was used
        assertEquals(AuthSessionChecks.Verdict.NEEDS_MANUAL_REVIEW, result.verdict());
        verify(probe).call(eq("GET"), any(), eq("Cookie"), eq("session=xyz"));
    }

    // ---------------- AUTH-11: JWT manipulation ----------------

    @Test
    void algNoneAcceptedIsCriticalAndClaimTamperIsCheckedSeparately() throws Exception {
        String token = jwtWithClaim("\"role\":\"user\"");
        LoginHttpClient http = mock(LoginHttpClient.class);
        when(http.post(any(), any())).thenReturn(new LoginHttpClient.Response(200, Map.of(), "{\"token\":\"" + token + "\"}"));
        ProbeHttpClient probe = mock(ProbeHttpClient.class);
        // sane probe with the real token succeeds; both forged attempts are also (wrongly) accepted
        when(probe.call(eq("GET"), any(), eq("Authorization"), anyString())).thenReturn(200);

        var checks = new AuthSessionChecks(new LoginFlowRunner(http), probe);
        var results = checks.checkJwt(bearerIdentity("https://app.example.com/me", null), "pw");

        assertEquals(2, results.size());
        assertTrue(results.stream().allMatch(r -> r.verdict() == AuthSessionChecks.Verdict.VULNERABLE));
        assertTrue(results.stream().anyMatch(r -> r.checkId().equals("AUTH-11a")));
        assertTrue(results.stream().anyMatch(r -> r.checkId().equals("AUTH-11b")));
    }

    @Test
    void aProperlyValidatedJwtIsNotVulnerable() throws Exception {
        String token = jwtWithClaim("\"role\":\"user\"");
        LoginHttpClient http = mock(LoginHttpClient.class);
        when(http.post(any(), any())).thenReturn(new LoginHttpClient.Response(200, Map.of(), "{\"token\":\"" + token + "\"}"));
        ProbeHttpClient probe = mock(ProbeHttpClient.class);
        when(probe.call(eq("GET"), any(), eq("Authorization"), eq("Bearer " + token))).thenReturn(200); // real token: ok
        when(probe.call(eq("GET"), any(), eq("Authorization"), argThat(h -> h != null && !h.equals("Bearer " + token))))
                .thenReturn(401); // any forged token: rejected

        var checks = new AuthSessionChecks(new LoginFlowRunner(http), probe);
        var results = checks.checkJwt(bearerIdentity("https://app.example.com/me", null), "pw");

        assertTrue(results.stream().allMatch(r -> r.verdict() == AuthSessionChecks.Verdict.NOT_VULNERABLE));
    }

    @Test
    void aNonJwtTokenIsManualReviewNotAFalsePositive() throws Exception {
        LoginHttpClient http = mock(LoginHttpClient.class);
        when(http.post(any(), any())).thenReturn(new LoginHttpClient.Response(200, Map.of(), "{\"token\":\"opaque-not-a-jwt\"}"));
        var checks = new AuthSessionChecks(new LoginFlowRunner(http), mock(ProbeHttpClient.class));
        var results = checks.checkJwt(bearerIdentity("https://app.example.com/me", null), "pw");
        assertEquals(1, results.size());
        assertEquals(AuthSessionChecks.Verdict.NEEDS_MANUAL_REVIEW, results.get(0).verdict());
    }

    @Test
    void cookieIdentitiesSkipJwtChecksEntirely() {
        var checks = new AuthSessionChecks(mock(LoginFlowRunner.class), mock(ProbeHttpClient.class));
        var results = checks.checkJwt(cookieIdentity("https://app.example.com/me", null), "pw");
        assertEquals(1, results.size());
        assertEquals(AuthSessionChecks.Verdict.NEEDS_MANUAL_REVIEW, results.get(0).verdict());
    }
}
