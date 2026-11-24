package com.sentinelops.service.logic;

import java.util.List;
import java.util.Map;

/** Sends one login POST (faked in tests). The caller must validate the host/addresses BEFORE calling this. */
public interface LoginHttpClient {

    record Response(int status, Map<String, List<String>> headers, String body) {}

    /** POSTs {@code jsonBody} as JSON to {@code url}. Never follows redirects. */
    Response post(String url, String jsonBody) throws Exception;
}
