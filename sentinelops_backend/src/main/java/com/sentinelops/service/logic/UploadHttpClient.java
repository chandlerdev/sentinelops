package com.sentinelops.service.logic;

/** Multipart upload + a plain GET to try to fetch the result back (faked in tests). */
public interface UploadHttpClient {

    /** {@code body} is capped and text-decoded; good enough to look for a short marker string in it. */
    record Result(int status, String body) {}

    Result uploadMultipart(String url, String fieldName, String filename, byte[] content, String contentType,
                           String headerName, String headerValue) throws Exception;

    Result get(String url, String headerName, String headerValue) throws Exception;
}
