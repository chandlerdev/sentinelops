package com.sentinelops.service.scanner;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.ScanMode;
import com.sentinelops.entity.TargetKind;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Everything that reaches a container command line is validated, and the command has one fixed shape. */
class ScanContextAndRunnerTest {

    private static final String RUN = "11111111-2222-3333-4444-555555555555";

    private static ScanContext ctx(TargetKind kind, String host, String url) {
        return ScanContext.of(RUN, kind, host, url, false, ScanMode.PASSIVE, List.of("93.184.216.34"),
                "X-Pentest", "sentinelops/e1");
    }

    // ---- ScanContext ----

    @Test
    void domainDefaultsToHttpsAndPort443() {
        var c = ctx(TargetKind.DOMAIN, "app.example.com", null);
        assertEquals("https://app.example.com", c.url());
        assertEquals(443, c.port());
        assertTrue(c.https());
    }

    @Test
    void explicitHttpUrlAndPortAreKept() {
        var c = ctx(TargetKind.DOMAIN, "app.example.com", "http://app.example.com:8080/shop");
        assertEquals(8080, c.port());
        assertFalse(c.https());
    }

    @Test
    void urlOnAnotherHostIsRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> ctx(TargetKind.DOMAIN, "app.example.com", "https://evil.example.org/"));
    }

    @Test
    void urlWithCredentialsOrShellCharactersIsRefused() {
        for (String bad : List.of("https://user:pw@app.example.com/", "https://app.example.com/a b",
                "https://app.example.com/;id", "https://app.example.com/$(id)", "https://app.example.com/`id`",
                "https://app.example.com/\"x", "ftp://app.example.com/")) {
            assertThrows(IllegalArgumentException.class, () -> ctx(TargetKind.DOMAIN, "app.example.com", bad), bad);
        }
    }

    @Test
    void hostThatLooksLikeAnOptionOrInjectionIsRefused() {
        for (String bad : List.of("-oX", "--help", "a b.com", "a.com;id", "a.com\n", "", "a..com", "A.COM$")) {
            assertThrows(IllegalArgumentException.class, () -> ctx(TargetKind.DOMAIN, bad, null), bad);
        }
        assertThrows(IllegalArgumentException.class, () -> ctx(TargetKind.IP, "10.0.0.1;id", null));
        assertThrows(IllegalArgumentException.class, () -> ctx(TargetKind.IP, "-1.2.3.4", null));
    }

    @Test
    void badRunIdHeaderOrAddressIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> ScanContext.of("../x", TargetKind.DOMAIN, "a.com", null,
                false, ScanMode.PASSIVE, List.of(), "X-Pentest", "v"));
        assertThrows(IllegalArgumentException.class, () -> ScanContext.of(RUN, TargetKind.DOMAIN, "a.com", null,
                false, ScanMode.PASSIVE, List.of(), "X Pentest", "v"));
        assertThrows(IllegalArgumentException.class, () -> ScanContext.of(RUN, TargetKind.DOMAIN, "a.com", null,
                false, ScanMode.PASSIVE, List.of(), "X-Pentest", "v\nInjected: 1"));
        assertThrows(IllegalArgumentException.class, () -> ScanContext.of(RUN, TargetKind.DOMAIN, "a.com", null,
                false, ScanMode.PASSIVE, List.of("1.2.3.4; rm"), "X-Pentest", "v"));
    }

    @Test
    void cidrHasNoUrl() {
        var c = ctx(TargetKind.CIDR, "203.0.113.0/28", null);
        assertNull(c.url());
    }

    // ---- DockerRunner command shape ----

    private DockerRunner runner() {
        return new DockerRunner((argv, t) -> new CommandExecutor.Result(0, false, ""), new AppProperties());
    }

    private DockerRunner.RunSpec spec(String network, List<String> pins, List<String> command) {
        return new DockerRunner.RunSpec(DockerRunner.containerName("nuclei", RUN), "projectdiscovery/nuclei:latest",
                network, "app.example.com", pins, Path.of("scan-work", RUN), "/out", command, Duration.ofMinutes(5));
    }

    @Test
    void commandHasOneFixedSafeShape() {
        List<String> argv = runner().buildCommand(spec("sentinelops-scan", List.of("93.184.216.34"),
                List.of("-u", "https://app.example.com")));

        assertEquals("docker", argv.get(0));
        assertEquals(List.of("run", "--rm", "--name", "sentinelops-nuclei-" + RUN), argv.subList(1, 5));
        assertTrue(argv.containsAll(List.of("--cap-drop", "ALL", "--security-opt", "no-new-privileges")));
        assertEquals("sentinelops-scan", argv.get(argv.indexOf("--network") + 1));
        assertEquals("app.example.com:93.184.216.34", argv.get(argv.indexOf("--add-host") + 1));
        assertFalse(argv.contains("--privileged"));
        assertFalse(argv.contains("-v"));
        assertFalse(argv.contains("sh"));
        // image comes before the tool arguments; the tool arguments are the tail, untouched
        int img = argv.indexOf("projectdiscovery/nuclei:latest");
        assertEquals(List.of("-u", "https://app.example.com"), argv.subList(img + 1, argv.size()));
        assertTrue(argv.get(argv.indexOf("--mount") + 1).startsWith("type=bind,source="));
    }

    @Test
    void noNetworkOrPinsWhenNotGiven() {
        List<String> argv = runner().buildCommand(spec("", List.of(), List.of("-u", "https://a.com")));
        assertFalse(argv.contains("--network"));
        assertFalse(argv.contains("--add-host"));
    }

    @Test
    void runnerRefusesUnsafeValues() {
        var r = runner();
        assertThrows(IllegalArgumentException.class, () -> r.buildCommand(new DockerRunner.RunSpec(
                "evil;name", "img", "", "a.com", List.of(), Path.of("x"), "/out", List.of(), Duration.ofMinutes(1))));
        assertThrows(IllegalArgumentException.class, () -> r.buildCommand(new DockerRunner.RunSpec(
                DockerRunner.containerName("nuclei", RUN), "img; rm -rf /", "", "a.com", List.of(), Path.of("x"),
                "/out", List.of(), Duration.ofMinutes(1))));
        assertThrows(IllegalArgumentException.class, () -> r.buildCommand(spec("net work", List.of(), List.of())));
        assertThrows(IllegalArgumentException.class, () -> r.buildCommand(spec("", List.of("1.2.3.4 --privileged"), List.of())));
        assertThrows(IllegalArgumentException.class, () -> r.buildCommand(spec("", List.of(), List.of("ok\nbad"))));
    }

    @Test
    void timeoutRemovesTheContainer() throws Exception {
        List<List<String>> calls = new ArrayList<>();
        var r = new DockerRunner((argv, t) -> {
            calls.add(argv);
            return calls.size() == 1 ? new CommandExecutor.Result(-1, true, "") : new CommandExecutor.Result(0, false, "");
        }, new AppProperties());
        r.run(spec("", List.of(), List.of("-u", "https://a.com")));
        assertEquals(List.of("docker", "rm", "-f", "sentinelops-nuclei-" + RUN), calls.get(1));
    }

    @Test
    void killIgnoresNamesThatAreNotOurs() {
        List<List<String>> calls = new ArrayList<>();
        var r = new DockerRunner((argv, t) -> {
            calls.add(argv);
            return new CommandExecutor.Result(0, false, "");
        }, new AppProperties());
        r.kill("some-other-app");
        r.kill("sentinelops-nuclei-x; rm");
        assertTrue(calls.isEmpty(), "never touch a container we did not create");
    }

    // ---- fixed command templates of the adapters ----

    @Test
    void passiveNucleiHasNoCveTemplatesAndAlwaysMarksTraffic() {
        var passive = new NucleiAdapter().command(ctx(TargetKind.DOMAIN, "app.example.com", null));
        assertFalse(passive.get(passive.indexOf("-tags") + 1).contains("cve"));
        assertTrue(passive.contains("X-Pentest: sentinelops/e1"));
        assertTrue(passive.get(passive.indexOf("-exclude-tags") + 1).contains("intrusive"));

        var active = new NucleiAdapter().command(ScanContext.of(RUN, TargetKind.DOMAIN, "app.example.com", null, false,
                ScanMode.ACTIVE, List.of("93.184.216.34"), "X-Pentest", "sentinelops/e1"));
        assertTrue(active.get(active.indexOf("-tags") + 1).contains("cve"));
    }

    @Test
    void zapUsesBaselineWhenPassiveAndFullScanOnlyWhenActive() {
        assertEquals("zap-baseline.py", new ZapAdapter().command(ctx(TargetKind.DOMAIN, "app.example.com", null)).get(0));
        var active = ScanContext.of(RUN, TargetKind.DOMAIN, "app.example.com", null, false, ScanMode.ACTIVE,
                List.of("93.184.216.34"), "X-Pentest", "sentinelops/e1");
        assertEquals("zap-full-scan.py", new ZapAdapter().command(active).get(0));
    }

    @Test
    void nmapPassiveIsConnectScanWithoutVersionDetectionAndUsesGateApprovedAddresses() {
        var c = new NmapAdapter().command(ctx(TargetKind.DOMAIN, "app.example.com", null));
        assertTrue(c.contains("-sT"));
        assertFalse(c.contains("-sV"));
        assertEquals("93.184.216.34", c.get(c.size() - 1));
        var cidr = new NmapAdapter().command(ctx(TargetKind.CIDR, "203.0.113.0/28", null));
        assertEquals("203.0.113.0/28", cidr.get(cidr.size() - 1));
    }

    @Test
    void testsslTargetsHostAndPort() {
        var c = new TestsslAdapter().command(ctx(TargetKind.DOMAIN, "app.example.com", "https://app.example.com:8443/"));
        assertEquals("app.example.com:8443", c.get(c.size() - 1));
    }
}
