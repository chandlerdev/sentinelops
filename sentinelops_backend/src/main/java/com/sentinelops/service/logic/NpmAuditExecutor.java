package com.sentinelops.service.logic;

/** Runs "npm audit" against an uploaded package-lock.json and returns its raw JSON report (faked in tests). */
public interface NpmAuditExecutor {
    String run(String packageLockJson) throws Exception;
}
