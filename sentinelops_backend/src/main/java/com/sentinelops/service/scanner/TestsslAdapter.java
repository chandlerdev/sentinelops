package com.sentinelops.service.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.ScanCategory;
import com.sentinelops.entity.Severity;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** testssl.sh: protocol, cipher, certificate and known-TLS-weakness checks (TLS category, https targets). */
@Component
public class TestsslAdapter implements ScannerAdapter {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Override public String id() { return "testssl"; }

    @Override public boolean supports(ScanCategory c) { return c == ScanCategory.TLS; }

    @Override public String image(AppProperties.Engine e) { return e.getTestsslImage(); }

    @Override public String outputFile() { return "testssl.json"; }

    /** testssl uses non-zero codes for findings; codes of 240 and above mean the run itself failed. */
    @Override public boolean acceptsExit(int code) { return code >= 0 && code < 240; }

    @Override
    public List<String> command(ScanContext ctx) {
        return List.of("--warnings", "batch", "--color", "0", "--quiet",
                "--jsonfile", containerOutDir() + "/" + outputFile(),
                ctx.host() + ":" + ctx.port());
    }

    @Override
    public List<NormalizedFinding> parse(Path outDir, ScanContext ctx) throws IOException {
        JsonNode root = JSON.readTree(ScannerAdapter.readCapped(outDir.resolve(outputFile())));
        JsonNode rows = root.isArray() ? root : root.path("scanResult");
        // Newer layout: scanResult[] objects holding arrays of rows (protocols, ciphers, vulnerabilities, ...).
        List<JsonNode> flat = new ArrayList<>();
        for (JsonNode r : rows) {
            if (r.has("id")) {
                flat.add(r);
            } else {
                for (JsonNode section : r) {
                    if (section.isArray()) section.forEach(flat::add);
                }
            }
        }
        List<NormalizedFinding> out = new ArrayList<>();
        for (JsonNode r : flat) {
            Severity sev = severity(r.path("severity").asText(""));
            if (sev == null) continue;
            String id = r.path("id").asText("testssl");
            out.add(new NormalizedFinding(id, "TLS: " + id.replace('_', ' '), sev,
                    ctx.host() + ":" + ctx.port(), r.path("finding").asText(""),
                    "Disable obsolete protocols and weak ciphers, use certificates from a trusted CA with a valid chain "
                            + "and expiry, and patch the TLS library. Re-run the TLS check afterwards.",
                    r.path("cve").asText(null)));
        }
        return out;
    }

    /** null = not a problem (OK / INFO). */
    static Severity severity(String s) {
        return switch (s.toUpperCase()) {
            case "CRITICAL" -> Severity.CRITICAL;
            case "HIGH" -> Severity.HIGH;
            case "MEDIUM" -> Severity.MEDIUM;
            case "LOW", "WARN" -> Severity.LOW;
            default -> null;
        };
    }
}
