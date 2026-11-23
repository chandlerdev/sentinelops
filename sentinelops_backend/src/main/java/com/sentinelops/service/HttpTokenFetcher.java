package com.sentinelops.service;

import java.util.Optional;

/** Fetches a tiny text file from a URL for HTTP-file ownership verification (faked in tests). */
public interface HttpTokenFetcher {
    /** @return the response body (trimmed, size-limited) on HTTP 200, otherwise empty. Never follows redirects. */
    Optional<String> fetch(String url) throws Exception;
}
