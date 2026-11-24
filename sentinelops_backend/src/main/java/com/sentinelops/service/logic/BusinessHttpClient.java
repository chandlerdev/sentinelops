package com.sentinelops.service.logic;

/** Sends one JSON POST/PUT, optionally carrying a session header (faked in tests). */
public interface BusinessHttpClient {

    record Result(int status) {}

    Result send(String method, String url, String jsonBody, String headerName, String headerValue) throws Exception;
}
