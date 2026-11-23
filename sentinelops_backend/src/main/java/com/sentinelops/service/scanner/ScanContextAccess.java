package com.sentinelops.service.scanner;

/** Lets services outside this package ask the same question the scan context asks about credential headers. */
public final class ScanContextAccess {
    private ScanContextAccess() {}

    public static boolean forbidden(String headerName) {
        return ScanContext.FORBIDDEN_AUTH_HEADERS.contains(headerName.toLowerCase());
    }
}
