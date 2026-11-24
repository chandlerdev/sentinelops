package com.sentinelops.service.logic;

import com.sentinelops.entity.SessionType;
import com.sentinelops.entity.TestIdentity;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** The runner captures a session on success and never invents one on failure or malformed output. */
class LoginFlowRunnerTest {

    private static TestIdentity identity(SessionType type, String tokenPath) {
        return new TestIdentity("i1", "t1", "User A", "https://app.example.com/login", "email", "password",
                "user@example.com", "enc", tokenPath, type, null, null, "POST", "tess@x.com");
    }

    @Test
    void capturesABearerTokenAtTheConfiguredPath() throws Exception {
        LoginHttpClient http = mock(LoginHttpClient.class);
        when(http.post(eq("https://app.example.com/login"), contains("user@example.com")))
                .thenReturn(new LoginHttpClient.Response(200, Map.of(), "{\"data\":{\"token\":\"abc.def.ghi\"}}"));
        var outcome = new LoginFlowRunner(http).attempt(identity(SessionType.HEADER_BEARER, "data.token"), "pw");

        assertTrue(outcome.success());
        assertTrue(outcome.sessionCaptured());
        assertEquals("abc.def.ghi", outcome.sessionValue());
    }

    @Test
    void neverSendsThePasswordInTheResultAndNeverSendsItInTheUrl() throws Exception {
        LoginHttpClient http = mock(LoginHttpClient.class);
        when(http.post(any(), any())).thenReturn(new LoginHttpClient.Response(200, Map.of(), "{\"token\":\"x\"}"));
        var outcome = new LoginFlowRunner(http).attempt(identity(SessionType.HEADER_BEARER, null), "s3cr3t-pw");

        verify(http).post(eq("https://app.example.com/login"), contains("s3cr3t-pw")); // only in the POST body
        assertFalse(outcome.toString().contains("s3cr3t-pw"));
        assertFalse(outcome.detail().contains("s3cr3t-pw"));
    }

    @Test
    void capturesACookieWhenSessionTypeIsCookie() throws Exception {
        LoginHttpClient http = mock(LoginHttpClient.class);
        when(http.post(any(), any())).thenReturn(new LoginHttpClient.Response(200,
                Map.of("set-cookie", List.of("session=abc; HttpOnly")), "{}"));
        var outcome = new LoginFlowRunner(http).attempt(identity(SessionType.COOKIE, null), "pw");

        assertTrue(outcome.success());
        assertEquals("session=abc; HttpOnly", outcome.sessionValue());
    }

    @Test
    void aNonSuccessStatusIsReportedAsFailureWithNoSession() throws Exception {
        LoginHttpClient http = mock(LoginHttpClient.class);
        when(http.post(any(), any())).thenReturn(new LoginHttpClient.Response(401, Map.of(), "{\"error\":\"bad creds\"}"));
        var outcome = new LoginFlowRunner(http).attempt(identity(SessionType.HEADER_BEARER, null), "pw");

        assertFalse(outcome.success());
        assertFalse(outcome.sessionCaptured());
        assertEquals(401, outcome.httpStatus());
    }

    @Test
    void aMissingTokenPathIsReportedAsFailureNotACrash() throws Exception {
        LoginHttpClient http = mock(LoginHttpClient.class);
        when(http.post(any(), any())).thenReturn(new LoginHttpClient.Response(200, Map.of(), "{\"ok\":true}"));
        var outcome = new LoginFlowRunner(http).attempt(identity(SessionType.HEADER_BEARER, "data.token"), "pw");

        assertFalse(outcome.success());
        assertFalse(outcome.sessionCaptured());
    }

    @Test
    void aNetworkFailureIsReportedNotThrown() throws Exception {
        LoginHttpClient http = mock(LoginHttpClient.class);
        when(http.post(any(), any())).thenThrow(new java.net.ConnectException("refused"));
        var outcome = new LoginFlowRunner(http).attempt(identity(SessionType.HEADER_BEARER, null), "pw");

        assertFalse(outcome.success());
        assertNotNull(outcome.detail());
    }
}
