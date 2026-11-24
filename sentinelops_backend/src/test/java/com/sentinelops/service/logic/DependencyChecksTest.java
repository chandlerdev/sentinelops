package com.sentinelops.service.logic;

import com.sentinelops.entity.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Parses the REAL output of "npm audit --package-lock-only --json" (captured once against an actual
 * lodash@4.17.4 package-lock.json on this machine, not guessed from documentation).
 */
class DependencyChecksTest {

    // Trimmed to 2 of the 9 real advisories lodash@4.17.4 returned, to keep the fixture readable; the shape
    // (vulnerabilities -> package -> severity/via/range/fixAvailable, metadata) is exactly what npm produced.
    private static final String REAL_NPM_AUDIT_JSON = """
        {
          "auditReportVersion": 2,
          "vulnerabilities": {
            "lodash": {
              "name": "lodash",
              "severity": "critical",
              "isDirect": false,
              "via": [
                {
                  "source": 1106900,
                  "name": "lodash",
                  "dependency": "lodash",
                  "title": "Prototype Pollution in lodash",
                  "url": "https://github.com/advisories/GHSA-fvqr-27wr-82fm",
                  "severity": "moderate",
                  "cwe": ["CWE-471", "CWE-1321"],
                  "cvss": { "score": 6.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" },
                  "range": "<4.17.5"
                },
                {
                  "source": 1106913,
                  "name": "lodash",
                  "dependency": "lodash",
                  "title": "Command Injection in lodash",
                  "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
                  "severity": "high",
                  "cwe": ["CWE-77", "CWE-94"],
                  "cvss": { "score": 7.2, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" },
                  "range": "<4.17.21"
                }
              ],
              "effects": [],
              "range": "<=4.17.23",
              "nodes": ["node_modules/lodash"],
              "fixAvailable": true
            }
          },
          "metadata": {
            "vulnerabilities": { "info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 1, "total": 1 },
            "dependencies": { "prod": 1, "dev": 1, "optional": 1, "peer": 1, "peerOptional": 0, "total": 1 }
          }
        }
        """;

    @Test
    void parsesARealVulnerablePackageIntoAFinding() throws Exception {
        NpmAuditExecutor exec = mock(NpmAuditExecutor.class);
        when(exec.run(any())).thenReturn(REAL_NPM_AUDIT_JSON);

        List<com.sentinelops.service.scanner.NormalizedFinding> findings = new DependencyChecks(exec).check("{}");

        assertEquals(1, findings.size());
        var f = findings.get(0);
        assertEquals(Severity.CRITICAL, f.severity());
        assertTrue(f.title().contains("lodash"));
        assertTrue(f.location().contains("lodash"));
        assertTrue(f.description().contains("Prototype Pollution"));
        assertTrue(f.description().contains("Command Injection"));
        assertTrue(f.remediation().toLowerCase().contains("npm audit fix") || f.remediation().toLowerCase().contains("update"));
        assertTrue(f.references().contains("GHSA-fvqr-27wr-82fm"));
    }

    @Test
    void aCleanManifestProducesNoFindings() throws Exception {
        NpmAuditExecutor exec = mock(NpmAuditExecutor.class);
        when(exec.run(any())).thenReturn("{\"auditReportVersion\":2,\"vulnerabilities\":{},\"metadata\":{}}");

        List<com.sentinelops.service.scanner.NormalizedFinding> findings = new DependencyChecks(exec).check("{}");
        assertTrue(findings.isEmpty());
    }

    @Test
    void aTransitiveDependencyChainViaIsHandled() throws Exception {
        // npm sometimes lists "via" as a plain package-name string for a dependency-of-a-dependency chain,
        // not a full advisory object - this must not crash the parser.
        String json = "{\"vulnerabilities\":{\"foo\":{\"name\":\"foo\",\"severity\":\"high\",\"via\":[\"bar\"],\"range\":\"*\",\"fixAvailable\":false}}}";
        NpmAuditExecutor exec = mock(NpmAuditExecutor.class);
        when(exec.run(any())).thenReturn(json);

        var findings = new DependencyChecks(exec).check("{}");
        assertEquals(1, findings.size());
        assertTrue(findings.get(0).description().contains("bar"));
    }

    @Test
    void executorFailureIsPropagatedNotSwallowed() {
        NpmAuditExecutor exec = mock(NpmAuditExecutor.class);
        assertThrows(Exception.class, () -> {
            when(exec.run(any())).thenThrow(new java.io.IOException("npm not found"));
            new DependencyChecks(exec).check("{}");
        });
    }
}
