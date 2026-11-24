package com.sentinelops.service.logic;

import com.sentinelops.entity.Severity;
import com.sentinelops.entity.SessionType;
import com.sentinelops.entity.TestIdentity;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * Phase 3 of the logic-testing engine (H: file upload, FILE-06 extension/type bypass; see
 * PENTEST_COVERAGE_PLAN.md). A finding needs two independent facts, never one odd response: the upload
 * call must look accepted, AND the exact bytes we sent must come back when we fetch the expected location
 * — proving the file was really stored under the dangerous name, not that the server just said "200 OK".
 */
@Component
public class UploadChecks {

    public enum Verdict { VULNERABLE, NOT_VULNERABLE, NEEDS_MANUAL_REVIEW }

    public record Result(String checkId, String title, Verdict verdict, Severity severity, String location,
                         String description, String remediation) {
        static Result review(String checkId, String title, String why) {
            return new Result(checkId, title, Verdict.NEEDS_MANUAL_REVIEW, Severity.INFORMATIONAL, null, why, null);
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();
    private final LoginFlowRunner login;
    private final UploadHttpClient http;

    public UploadChecks(LoginFlowRunner login, UploadHttpClient http) {
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

    private static String randomToken() {
        byte[] b = new byte[8];
        RANDOM.nextBytes(b);
        return HexFormat.of().formatHex(b);
    }

    /**
     * @param identity null = anonymous (unauthenticated) upload.
     * @return two results: a single dangerous extension, then a double extension (blocklist-bypass shape).
     */
    public List<Result> checkExtensionBypass(TestIdentity identity, String password, String uploadUrl,
                                             String fieldName, String retrievalUrlTemplate) {
        List<Result> out = new ArrayList<>();
        String hName = null, hVal = null;
        if (identity != null) {
            var outcome = login.attempt(identity, password);
            if (!outcome.success() || !outcome.sessionCaptured()) {
                String why = "Could not log in as " + identity.getLabel() + ": " + outcome.detail();
                out.add(Result.review("FILE-06a", "Dangerous extension accepted on upload", why));
                out.add(Result.review("FILE-06b", "Double-extension upload accepted", why));
                return out;
            }
            hName = headerName(identity);
            hVal = headerValue(identity, outcome.sessionValue());
        }
        out.add(tryOne("FILE-06a", "Dangerous extension accepted on upload", "sentinelops-" + randomToken() + ".php",
                uploadUrl, fieldName, retrievalUrlTemplate, hName, hVal));
        out.add(tryOne("FILE-06b", "Double-extension upload accepted", "sentinelops-" + randomToken() + ".jpg.php",
                uploadUrl, fieldName, retrievalUrlTemplate, hName, hVal));
        return out;
    }

    private Result tryOne(String checkId, String title, String filename, String uploadUrl, String fieldName,
                          String retrievalUrlTemplate, String hName, String hVal) {
        String marker = "SentinelOps-FILE-06-" + randomToken();
        byte[] content = (marker + "\n").getBytes(StandardCharsets.UTF_8);

        UploadHttpClient.Result uploadRes;
        try {
            uploadRes = http.uploadMultipart(uploadUrl, fieldName, filename, content, "image/jpeg", hName, hVal);
        } catch (Exception ex) {
            return Result.review(checkId, title, "The upload request could not be sent: " + ex.getClass().getSimpleName());
        }
        if (!ok(uploadRes.status())) {
            return new Result(checkId, title, Verdict.NOT_VULNERABLE, Severity.INFORMATIONAL, uploadUrl, null, null);
        }

        String retrievalUrl = retrievalUrlTemplate.replace("{filename}", filename);
        UploadHttpClient.Result getRes;
        try {
            getRes = http.get(retrievalUrl, hName, hVal);
        } catch (Exception ex) {
            return Result.review(checkId, title, "The upload returned " + uploadRes.status()
                    + " but the file could not be fetched back to confirm it: " + ex.getClass().getSimpleName());
        }
        if (ok(getRes.status()) && getRes.body() != null && getRes.body().contains(marker)) {
            return new Result(checkId, title, Verdict.VULNERABLE, Severity.HIGH, retrievalUrl,
                    "A file named \"" + filename + "\" was accepted and is now served back from " + retrievalUrl
                            + " with its original (dangerous) extension intact.",
                    "Validate uploaded file types by content, not by filename; store uploads outside the web root or "
                            + "under a randomised, extension-stripped name, and never execute scripts from the upload directory.");
        }
        return Result.review(checkId, title, "The upload returned " + uploadRes.status() + " but the file could not be "
                + "confirmed at " + retrievalUrl + " (status " + getRes.status() + "). Check the retrieval URL template.");
    }
}
