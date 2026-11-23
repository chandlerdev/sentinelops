package com.sentinelops.service.scanner;

import com.sentinelops.entity.Severity;

/** A tool result reduced to the platform's own shape. */
public record NormalizedFinding(
        String ruleId,
        String title,
        Severity severity,
        String location,
        String description,
        String remediation,
        String references) {

    public NormalizedFinding {
        title = cap(title, 500);
        ruleId = cap(ruleId, 250);
        location = cap(location, 1000);
        description = cap(description, 4000);
        remediation = cap(remediation, 4000);
        references = cap(references, 1000);
    }

    static String cap(String s, int max) {
        if (s == null) return null;
        s = s.strip();
        return s.length() <= max ? s : s.substring(0, max - 3) + "...";
    }
}
