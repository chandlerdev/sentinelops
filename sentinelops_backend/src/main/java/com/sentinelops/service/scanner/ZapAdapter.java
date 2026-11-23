package com.sentinelops.service.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.ScanCategory;
import com.sentinelops.entity.ScanMode;
import com.sentinelops.entity.Severity;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * OWASP ZAP. PASSIVE runs the baseline script (spider + passive rules; it does not attack the site).
 * ACTIVE runs the full-scan script (active attack rules), only reachable when all active-scan switches are on.
 */
@Component
public class ZapAdapter implements ScannerAdapter {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Override public String id() { return "zap"; }

    @Override public boolean supports(ScanCategory c) { return c == ScanCategory.WEB; }

    @Override public String image(AppProperties.Engine e) { return e.getZapImage(); }

    @Override public String containerOutDir() { return "/zap/wrk"; }

    @Override public String outputFile() { return "zap.json"; }

    /** ZAP's Docker scripts read ZAP_AUTH_HEADER / _VALUE / _SITE; the site limit keeps the secret on the target host. */
    @Override
    public java.util.Map<String, String> secretEnv(ScanContext ctx) {
        return ctx.authenticated()
                ? java.util.Map.of("ZAP_AUTH_HEADER", ctx.authHeaderName(),
                                   "ZAP_AUTH_HEADER_VALUE", ctx.authHeaderValue(),
                                   "ZAP_AUTH_HEADER_SITE", ctx.host())
                : java.util.Map.of();
    }

    /** 0 = clean, 1 = failures found, 2 = warnings found. 3+ = the scan itself failed. */
    @Override public boolean acceptsExit(int code) { return code >= 0 && code <= 2; }

    @Override
    public List<String> command(ScanContext ctx) {
        boolean active = ctx.mode() == ScanMode.ACTIVE;
        List<String> c = new ArrayList<>(List.of(
                active ? "zap-full-scan.py" : "zap-baseline.py",
                "-t", ctx.url(),
                "-J", outputFile(),
                "-I",
                active ? "-T" : "-m", active ? "25" : "5"));
        // Marks every request so the site owner's defenders can recognise an authorized test.
        c.add("-z");
        c.add(markerConfig(ctx));
        return c;
    }

    static String markerConfig(ScanContext ctx) {
        return "-config replacer.full_list(0).description=sentinelops"
                + " -config replacer.full_list(0).enabled=true"
                + " -config replacer.full_list(0).matchtype=REQ_HEADER"
                + " -config replacer.full_list(0).matchstring=" + ctx.headerName()
                + " -config replacer.full_list(0).replacement=" + ctx.headerValue();
    }

    @Override
    public List<NormalizedFinding> parse(Path outDir, ScanContext ctx) throws IOException {
        JsonNode root = JSON.readTree(ScannerAdapter.readCapped(outDir.resolve(outputFile())));
        List<NormalizedFinding> out = new ArrayList<>();
        for (JsonNode site : root.path("site")) {
            for (JsonNode alert : site.path("alerts")) {
                String rule = alert.path("pluginid").asText(alert.path("alertRef").asText("zap"));
                List<String> uris = new ArrayList<>();
                for (JsonNode inst : alert.path("instances")) {
                    String u = inst.path("uri").asText("");
                    if (!u.isEmpty() && uris.size() < 10) uris.add(u);
                }
                int total = alert.path("instances").size();
                String location = uris.isEmpty() ? site.path("@name").asText(ctx.url()) : String.join(" ", uris);
                if (total > uris.size() && !uris.isEmpty()) location += " (+" + (total - uris.size()) + " more)";

                String cwe = alert.path("cweid").asText("");
                String refs = ScannerAdapter.stripHtml(alert.path("reference").asText(""));
                if (!cwe.isBlank() && !"-1".equals(cwe) && !"0".equals(cwe)) refs = ("CWE-" + cwe + " " + refs).strip();

                out.add(new NormalizedFinding(rule,
                        alert.path("alert").asText(alert.path("name").asText("ZAP alert")),
                        severity(alert.path("riskcode").asText("0")),
                        location,
                        ScannerAdapter.stripHtml(alert.path("desc").asText(null)),
                        ScannerAdapter.stripHtml(alert.path("solution").asText(null)),
                        refs));
            }
        }
        return out;
    }

    static Severity severity(String riskCode) {
        return switch (riskCode) {
            case "3" -> Severity.HIGH;          // ZAP's top level is "High"
            case "2" -> Severity.MEDIUM;
            case "1" -> Severity.LOW;
            default -> Severity.INFORMATIONAL;
        };
    }
}
