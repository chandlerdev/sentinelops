package com.sentinelops.service.logic;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelops.entity.Severity;
import com.sentinelops.service.scanner.NormalizedFinding;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Phase 6 of the logic-testing engine (L: dependency / SCA scanning; see PENTEST_COVERAGE_PLAN.md). Runs
 * "npm audit" against an uploaded package-lock.json and turns its report into findings. Unlike the
 * VULNERABLE/NOT_VULNERABLE/NEEDS_MANUAL_REVIEW logic checks, npm's own advisory database already IS the
 * confirmation (a known CVE/GHSA matched against the exact locked version) - every entry becomes a
 * candidate finding, same as a scanner's output, still validated=false until a tester confirms it.
 *
 * Real output schema verified directly against npm (not guessed): {@code npm audit --package-lock-only
 * --json} returns a top-level "vulnerabilities" object keyed by package name, each with "severity", "via"
 * (advisory objects or, for transitive chains, plain package-name strings), "range" and "fixAvailable".
 */
@Component
public class DependencyChecks {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Map<String, Severity> SEVERITY = Map.of(
            "critical", Severity.CRITICAL, "high", Severity.HIGH, "moderate", Severity.MEDIUM,
            "low", Severity.LOW, "info", Severity.INFORMATIONAL);

    private final NpmAuditExecutor executor;

    public DependencyChecks(NpmAuditExecutor executor) {
        this.executor = executor;
    }

    /** @return the findings npm's own advisory database reports; empty if the manifest has no known issues. */
    public List<NormalizedFinding> check(String packageLockJson) throws Exception {
        String raw = executor.run(packageLockJson);
        JsonNode root = JSON.readTree(raw);
        JsonNode vulns = root.path("vulnerabilities");
        List<NormalizedFinding> out = new ArrayList<>();
        if (!vulns.isObject()) return out;

        Iterator<Map.Entry<String, JsonNode>> fields = vulns.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> e = fields.next();
            String pkg = e.getKey();
            JsonNode v = e.getValue();
            Severity sev = SEVERITY.getOrDefault(v.path("severity").asText("").toLowerCase(), Severity.MEDIUM);

            List<String> titles = new ArrayList<>();
            List<String> refs = new ArrayList<>();
            for (JsonNode via : v.path("via")) {
                if (via.isTextual()) {
                    titles.add("depends on vulnerable package \"" + via.asText() + "\"");
                } else {
                    titles.add(via.path("title").asText(pkg + " advisory"));
                    String url = via.path("url").asText(null);
                    if (url != null) refs.add(url);
                    for (JsonNode cwe : via.path("cwe")) refs.add(cwe.asText());
                }
            }
            String range = v.path("range").asText("");
            JsonNode fix = v.path("fixAvailable");
            String remediation = fix.isBoolean() && fix.asBoolean()
                    ? "Run \"npm audit fix\", or update \"" + pkg + "\" to a version outside " + range + "."
                    : fix.isObject()
                        ? "Upgrade \"" + pkg + "\" to " + fix.path("name").asText(pkg) + "@" + fix.path("version").asText("latest")
                                + (fix.path("isSemVerMajor").asBoolean(false) ? " (a major version bump)." : ".")
                        : "No automated fix is available yet; review the advisory and consider an alternative package.";

            out.add(new NormalizedFinding("npm-" + pkg, pkg + " has a known vulnerability (" + v.path("severity").asText("unknown") + ")",
                    sev, pkg + " " + range, String.join("; ", titles), remediation, String.join(", ", refs)));
        }
        return out;
    }
}
