package com.sentinelops.service.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.ScanCategory;
import com.sentinelops.entity.ScanMode;
import com.sentinelops.entity.Severity;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Nuclei: template-based checks for exposures, misconfigurations and known CVEs (WEB and API targets). */
@Component
public class NucleiAdapter implements ScannerAdapter {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Override public String id() { return "nuclei"; }

    @Override public boolean supports(ScanCategory c) { return c == ScanCategory.WEB || c == ScanCategory.API; }

    @Override public String image(AppProperties.Engine e) { return e.getNucleiImage(); }

    @Override public String outputFile() { return "nuclei.jsonl"; }

    static final String AUTH_FILE = "auth-headers.txt";

    @Override
    public java.util.Map<String, String> secretFiles(ScanContext ctx) {
        return ctx.authenticated()
                ? java.util.Map.of(AUTH_FILE, ctx.authHeaderName() + ": " + ctx.authHeaderValue() + "\n")
                : java.util.Map.of();
    }

    @Override
    public List<String> command(ScanContext ctx) {
        List<String> c = new ArrayList<>(List.of(
                "-u", ctx.url(),
                "-jsonl", "-o", containerOutDir() + "/" + outputFile(),
                "-silent", "-no-color", "-disable-update-check", "-no-interactsh",
                "-H", ctx.headerLine(),
                "-rate-limit", "20", "-concurrency", "10", "-timeout", "10", "-retries", "1",
                "-exclude-tags", "dos,fuzz,intrusive,bruteforce"));
        if (ctx.authenticated()) {
            // The credential is read from a file so it is not visible in the process list. (-H accepts a file path.)
            c.add("-H");
            c.add(containerOutDir() + "/" + AUTH_FILE);
        }
        // PASSIVE: information-disclosure / misconfiguration / fingerprinting checks. ACTIVE adds known-CVE checks.
        c.add("-tags");
        c.add(ctx.mode() == ScanMode.ACTIVE
                ? "tech,exposure,misconfig,token,takeover,cve"
                : "tech,exposure,misconfig,token,takeover");
        return c;
    }

    @Override
    public List<NormalizedFinding> parse(Path outDir, ScanContext ctx) throws IOException {
        // Nuclei writes no file when nothing matched; that is a valid, empty result.
        Path file = outDir.resolve(outputFile());
        if (!java.nio.file.Files.exists(file)) return List.of();
        String text = new String(ScannerAdapter.readCapped(file), StandardCharsets.UTF_8);
        List<NormalizedFinding> out = new ArrayList<>();
        for (String line : text.split("\\R")) {
            if (line.isBlank()) continue;
            JsonNode n;
            try { n = JSON.readTree(line); } catch (IOException ex) { continue; }
            JsonNode info = n.path("info");
            if (info.isMissingNode()) continue;
            String ruleId = n.path("template-id").asText("nuclei");
            String title = info.path("name").asText(ruleId);
            String location = n.path("matched-at").asText(n.path("host").asText(ctx.url()));

            List<String> refs = new ArrayList<>();
            JsonNode ref = info.path("reference");
            if (ref.isArray()) ref.forEach(r -> refs.add(r.asText()));
            else if (ref.isTextual()) refs.add(ref.asText());
            JsonNode cls = info.path("classification");
            addAll(refs, cls.path("cve-id"));
            addAll(refs, cls.path("cwe-id"));

            String remediation = info.path("remediation").asText(null);
            if (remediation == null || remediation.isBlank()) {
                remediation = "Review the matched resource and remove or restrict it; apply the vendor fix if a CVE is listed.";
            }
            out.add(new NormalizedFinding(ruleId, title, severity(info.path("severity").asText("info")), location,
                    info.path("description").asText(null), remediation, String.join(", ", refs)));
        }
        return out;
    }

    private static void addAll(List<String> into, JsonNode arrayOrText) {
        if (arrayOrText.isArray()) arrayOrText.forEach(x -> into.add(x.asText()));
        else if (arrayOrText.isTextual()) into.add(arrayOrText.asText());
    }

    static Severity severity(String s) {
        return switch (s.toLowerCase()) {
            case "critical" -> Severity.CRITICAL;
            case "high" -> Severity.HIGH;
            case "medium" -> Severity.MEDIUM;
            case "low" -> Severity.LOW;
            default -> Severity.INFORMATIONAL;
        };
    }
}
