package com.sentinelops.service.logic;

import com.sentinelops.entity.SessionType;
import com.sentinelops.entity.TestIdentity;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** A finding needs BOTH an accepted upload AND our own marker bytes coming back from the retrieval URL. */
class UploadChecksTest {

    private static TestIdentity identity() {
        return new TestIdentity("i1", "t1", "User A", "https://app.example.com/login", "email", "password",
                "u", "enc", "token", SessionType.HEADER_BEARER, null, null, "POST", "tess");
    }

    @Test
    void acceptedAndRetrievableWithTheExactMarkerIsVulnerable() throws Exception {
        // A server that really stores the upload: "get" echoes back whatever bytes were just uploaded.
        byte[][] lastContent = new byte[1][];
        UploadHttpClient http = mock(UploadHttpClient.class);
        when(http.uploadMultipart(any(), any(), any(), any(), any(), any(), any())).thenAnswer(inv -> {
            lastContent[0] = inv.getArgument(3);
            return new UploadHttpClient.Result(201, "{\"ok\":true}");
        });
        when(http.get(any(), any(), any())).thenAnswer(inv ->
                new UploadHttpClient.Result(200, new String(lastContent[0], java.nio.charset.StandardCharsets.UTF_8)));

        var checks = new UploadChecks(mock(LoginFlowRunner.class), http);
        var results = checks.checkExtensionBypass(null, null, "https://app.example.com/upload", "file",
                "https://app.example.com/uploads/{filename}");

        assertEquals(2, results.size());
        assertTrue(results.stream().allMatch(r -> r.verdict() == UploadChecks.Verdict.VULNERABLE));
        assertTrue(results.stream().allMatch(r -> r.severity() == com.sentinelops.entity.Severity.HIGH));
    }

    @Test
    void aServerThatIgnoresTheMarkerIsManualReviewNotVulnerable() throws Exception {
        // "get" returns something, but never the bytes we actually uploaded - cannot prove it's really our file.
        UploadHttpClient http = mock(UploadHttpClient.class);
        when(http.uploadMultipart(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new UploadHttpClient.Result(201, "{\"ok\":true}"));
        when(http.get(any(), any(), any())).thenReturn(new UploadHttpClient.Result(200, "<html>a generic page</html>"));

        var checks = new UploadChecks(mock(LoginFlowRunner.class), http);
        var results = checks.checkExtensionBypass(null, null, "https://app.example.com/upload", "file",
                "https://app.example.com/uploads/{filename}");

        assertTrue(results.stream().allMatch(r -> r.verdict() == UploadChecks.Verdict.NEEDS_MANUAL_REVIEW));
    }

    @Test
    void anUploadRejectedOutrightIsNotVulnerable() throws Exception {
        UploadHttpClient http = mock(UploadHttpClient.class);
        when(http.uploadMultipart(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new UploadHttpClient.Result(415, "unsupported media type"));

        var checks = new UploadChecks(mock(LoginFlowRunner.class), http);
        var results = checks.checkExtensionBypass(null, null, "https://app.example.com/upload", "file",
                "https://app.example.com/uploads/{filename}");

        assertTrue(results.stream().allMatch(r -> r.verdict() == UploadChecks.Verdict.NOT_VULNERABLE));
        verify(http, never()).get(any(), any(), any());
    }

    @Test
    void acceptedButNotRetrievableIsManualReviewNotAFalsePositive() throws Exception {
        UploadHttpClient http = mock(UploadHttpClient.class);
        when(http.uploadMultipart(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new UploadHttpClient.Result(200, "ok"));
        when(http.get(any(), any(), any())).thenReturn(new UploadHttpClient.Result(404, "not found"));

        var checks = new UploadChecks(mock(LoginFlowRunner.class), http);
        var results = checks.checkExtensionBypass(null, null, "https://app.example.com/upload", "file",
                "https://app.example.com/uploads/{filename}");

        assertTrue(results.stream().allMatch(r -> r.verdict() == UploadChecks.Verdict.NEEDS_MANUAL_REVIEW));
    }

    @Test
    void loginFailureIsManualReviewAndNeverUploadsAnything() throws Exception {
        LoginFlowRunner login = mock(LoginFlowRunner.class);
        when(login.attempt(any(), any())).thenReturn(new LoginFlowRunner.LoginOutcome(false, 401, false, null, "bad creds"));
        UploadHttpClient http = mock(UploadHttpClient.class);

        var checks = new UploadChecks(login, http);
        var results = checks.checkExtensionBypass(identity(), "pw", "https://app.example.com/upload", "file",
                "https://app.example.com/uploads/{filename}");

        assertEquals(2, results.size());
        assertTrue(results.stream().allMatch(r -> r.verdict() == UploadChecks.Verdict.NEEDS_MANUAL_REVIEW));
        verifyNoInteractions(http);
    }

    @Test
    void anAnonymousProbeNeverLogsIn() throws Exception {
        LoginFlowRunner login = mock(LoginFlowRunner.class);
        UploadHttpClient http = mock(UploadHttpClient.class);
        when(http.uploadMultipart(any(), any(), any(), any(), any(), isNull(), isNull()))
                .thenReturn(new UploadHttpClient.Result(415, "rejected"));

        var checks = new UploadChecks(login, http);
        checks.checkExtensionBypass(null, null, "https://app.example.com/upload", "file",
                "https://app.example.com/uploads/{filename}");

        verifyNoInteractions(login);
        verify(http, times(2)).uploadMultipart(any(), any(), any(), any(), any(), isNull(), isNull());
    }

    @Test
    void sendsTwoDistinctFilenamesOneDoubleExtension() throws Exception {
        UploadHttpClient http = mock(UploadHttpClient.class);
        when(http.uploadMultipart(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new UploadHttpClient.Result(415, "rejected"));
        var captor = org.mockito.ArgumentCaptor.forClass(String.class);

        var checks = new UploadChecks(mock(LoginFlowRunner.class), http);
        checks.checkExtensionBypass(null, null, "https://app.example.com/upload", "file",
                "https://app.example.com/uploads/{filename}");

        verify(http, times(2)).uploadMultipart(any(), any(), captor.capture(), any(), any(), any(), any());
        var names = captor.getAllValues();
        assertTrue(names.get(0).endsWith(".php") && !names.get(0).contains(".jpg"));
        assertTrue(names.get(1).endsWith(".jpg.php"));
    }
}
