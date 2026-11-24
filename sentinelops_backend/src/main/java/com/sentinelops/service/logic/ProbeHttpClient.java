package com.sentinelops.service.logic;

/** Sends one authenticated request to check whether a session still works (faked in tests). */
public interface ProbeHttpClient {

    /** {@code bodyLength} lets the IDOR check tell a real object apart from a same-status "soft 403" page. */
    record Result(int status, int bodyLength) {}

    /** {@code headerName}/{@code headerValue} carry the session (Authorization or Cookie). */
    Result callWithBody(String method, String url, String headerName, String headerValue) throws Exception;

    /** @return just the HTTP status code, for checks that don't need the body. */
    default int call(String method, String url, String headerName, String headerValue) throws Exception {
        return callWithBody(method, url, headerName, headerValue).status();
    }
}
