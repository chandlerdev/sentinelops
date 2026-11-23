package com.sentinelops.service.scanner;

import com.sentinelops.entity.ScanMode;
import com.sentinelops.entity.Severity;
import com.sentinelops.entity.TargetKind;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Parsers are tested against hand-written samples that follow each tool's documented output format.
 * They have NOT been checked against real tool output yet (no Docker on the dev PC): do that on the first lab run.
 */
class AdapterParsingTest {

    private static ScanContext ctx(TargetKind kind, String host) {
        return ScanContext.of("11111111-2222-3333-4444-555555555555", kind, host, null, false, ScanMode.PASSIVE,
                List.of("93.184.216.34"), "X-Pentest", "sentinelops/e1");
    }

    @Test
    void nucleiJsonlBecomesFindingsAndSkipsGarbageLines(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("nuclei.jsonl"), String.join("\n",
                "{\"template-id\":\"git-config\",\"info\":{\"name\":\"Git Config Exposure\",\"severity\":\"medium\","
                        + "\"description\":\"A .git/config file is public.\",\"remediation\":\"Block access to .git.\","
                        + "\"reference\":[\"https://example.org/a\"],\"classification\":{\"cwe-id\":[\"CWE-200\"]}},"
                        + "\"matched-at\":\"https://app.example.com/.git/config\",\"host\":\"app.example.com\"}",
                "this is not json",
                "{\"template-id\":\"tech-detect\",\"info\":{\"name\":\"Wappalyzer\",\"severity\":\"info\"},\"host\":\"app.example.com\"}",
                ""));
        var out = new NucleiAdapter().parse(dir, ctx(TargetKind.DOMAIN, "app.example.com"));

        assertEquals(2, out.size());
        assertEquals(Severity.MEDIUM, out.get(0).severity());
        assertEquals("https://app.example.com/.git/config", out.get(0).location());
        assertEquals("Block access to .git.", out.get(0).remediation());
        assertTrue(out.get(0).references().contains("CWE-200"));
        assertEquals(Severity.INFORMATIONAL, out.get(1).severity());
        assertNotNull(out.get(1).remediation(), "a generic fix hint is supplied when the template has none");
    }

    @Test
    void nucleiWithNoOutputFileMeansNothingFound(@TempDir Path dir) throws IOException {
        assertTrue(new NucleiAdapter().parse(dir, ctx(TargetKind.DOMAIN, "app.example.com")).isEmpty());
    }

    @Test
    void zapReportAlertsKeepRiskSolutionAndUrls(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("zap.json"), "{\"site\":[{\"@name\":\"https://app.example.com\",\"alerts\":["
                + "{\"pluginid\":\"10038\",\"alert\":\"Content Security Policy (CSP) Header Not Set\",\"riskcode\":\"2\","
                + "\"desc\":\"<p>CSP is missing &amp; useful.</p>\",\"solution\":\"<p>Set the header.</p>\","
                + "\"reference\":\"<p>https://example.org/csp</p>\",\"cweid\":\"693\","
                + "\"instances\":[{\"uri\":\"https://app.example.com/\"},{\"uri\":\"https://app.example.com/a\"}]},"
                + "{\"pluginid\":\"10015\",\"alert\":\"Re-examine Cache-control\",\"riskcode\":\"0\",\"instances\":[]}]}]}");
        var out = new ZapAdapter().parse(dir, ctx(TargetKind.DOMAIN, "app.example.com"));

        assertEquals(2, out.size());
        var csp = out.get(0);
        assertEquals(Severity.MEDIUM, csp.severity());
        assertEquals("CSP is missing & useful.", csp.description());
        assertEquals("Set the header.", csp.remediation());
        assertTrue(csp.location().contains("https://app.example.com/a"));
        assertTrue(csp.references().startsWith("CWE-693"));
        assertEquals(Severity.INFORMATIONAL, out.get(1).severity());
    }

    @Test
    void zapAcceptsOnlyItsDocumentedExitCodes() {
        var z = new ZapAdapter();
        assertTrue(z.acceptsExit(0) && z.acceptsExit(1) && z.acceptsExit(2));
        assertFalse(z.acceptsExit(3));
    }

    @Test
    void testsslKeepsOnlyRealProblems(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("testssl.json"), "[{\"id\":\"SSLv3\",\"severity\":\"OK\",\"finding\":\"not offered\"},"
                + "{\"id\":\"TLS1\",\"severity\":\"LOW\",\"finding\":\"offered (deprecated)\"},"
                + "{\"id\":\"cert_notAfter\",\"severity\":\"HIGH\",\"finding\":\"expired\"},"
                + "{\"id\":\"banner\",\"severity\":\"INFO\",\"finding\":\"nginx\"}]");
        var out = new TestsslAdapter().parse(dir, ctx(TargetKind.DOMAIN, "app.example.com"));

        assertEquals(2, out.size());
        assertEquals(Severity.LOW, out.get(0).severity());
        assertEquals(Severity.HIGH, out.get(1).severity());
        assertEquals("app.example.com:443", out.get(1).location());
    }

    @Test
    void nmapOpenPortsAreRatedByExposureRisk(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("nmap.xml"), "<?xml version=\"1.0\"?><nmaprun><host>"
                + "<address addr=\"93.184.216.34\" addrtype=\"ipv4\"/><ports>"
                + "<port protocol=\"tcp\" portid=\"443\"><state state=\"open\"/><service name=\"https\" product=\"nginx\" version=\"1.25\"/></port>"
                + "<port protocol=\"tcp\" portid=\"6379\"><state state=\"open\"/><service name=\"redis\"/></port>"
                + "<port protocol=\"tcp\" portid=\"22\"><state state=\"closed\"/></port>"
                + "</ports></host></nmaprun>");
        var out = new NmapAdapter().parse(dir, ctx(TargetKind.DOMAIN, "app.example.com"));

        assertEquals(2, out.size());
        assertEquals(Severity.INFORMATIONAL, out.get(0).severity());
        assertTrue(out.get(0).description().contains("nginx 1.25"));
        assertEquals(Severity.HIGH, out.get(1).severity());
        assertEquals("93.184.216.34:6379", out.get(1).location());
    }

    @Test
    void nmapParserRefusesXmlEntityTricks(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("nmap.xml"),
                "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><nmaprun>&e;</nmaprun>");
        assertThrows(IOException.class, () -> new NmapAdapter().parse(dir, ctx(TargetKind.DOMAIN, "app.example.com")));
    }

    @Test
    void missingOutputIsAnErrorNotAnEmptyResultForTheOtherTools(@TempDir Path dir) {
        var c = ctx(TargetKind.DOMAIN, "app.example.com");
        assertThrows(IOException.class, () -> new ZapAdapter().parse(dir, c));
        assertThrows(IOException.class, () -> new TestsslAdapter().parse(dir, c));
        assertThrows(IOException.class, () -> new NmapAdapter().parse(dir, c));
    }
}
