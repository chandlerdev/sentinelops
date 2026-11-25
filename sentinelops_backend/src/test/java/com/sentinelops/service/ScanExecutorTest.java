package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.repository.FindingRepository;
import com.sentinelops.repository.RetestRepository;
import com.sentinelops.repository.ScanRunRepository;
import com.sentinelops.service.scanner.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/** One run, start to finish, with a fake Docker (no containers are started). */
class ScanExecutorTest {

    private static final String RUN = "11111111-2222-3333-4444-555555555555";
    private static final String NUCLEI_OUT = "{\"template-id\":\"git-config\",\"info\":{\"name\":\"Git Config Exposure\","
            + "\"severity\":\"medium\"},\"matched-at\":\"https://app.example.com/.git/config\"}\n";

    @TempDir Path work;

    private AuthorizationGateService gate;
    private SettingsService settings;
    private AuditService audit;
    private AppProperties props;
    private ScanRunRepository scanRuns;
    private FindingRepository findings;
    private final Map<String, ScanRun> runs = new HashMap<>();
    private final List<Finding> savedFindings = new ArrayList<>();
    private final List<List<String>> dockerCalls = new ArrayList<>();
    private Consumer<Path> toolBehaviour;          // what the fake container writes into the mounted folder
    private CommandExecutor.Result toolResult;      // what the fake `docker run` returns
    private Runnable duringTool = () -> {};
    private Target target;
    private Authorization auth;
    private ScanExecutor executor;

    @BeforeEach
    void setUp() {
        gate = mock(AuthorizationGateService.class);
        settings = mock(SettingsService.class);
        audit = mock(AuditService.class);
        props = new AppProperties();
        props.getScan().getEngine().setEnabled(true);
        props.getScan().getEngine().setWorkDir(work.toString());
        props.getScan().getEngine().setScanNetwork("sentinelops-scan");

        scanRuns = mock(ScanRunRepository.class);
        when(scanRuns.save(any())).thenAnswer(i -> {
            ScanRun r = i.getArgument(0);
            runs.put(r.getId(), r);
            return r;
        });
        when(scanRuns.findById(any())).thenAnswer(i -> Optional.ofNullable(runs.get((String) i.getArgument(0))));

        findings = mock(FindingRepository.class);
        when(findings.save(any())).thenAnswer(i -> {
            Finding f = i.getArgument(0);
            if (!savedFindings.contains(f)) savedFindings.add(f);
            return f;
        });
        when(findings.findFirstByEngagementIdAndFingerprint(any(), any())).thenAnswer(i ->
                savedFindings.stream().filter(f -> Objects.equals(f.getFingerprint(), i.getArgument(1))).findFirst());

        toolBehaviour = dir -> write(dir, "nuclei.jsonl", NUCLEI_OUT);
        toolResult = new CommandExecutor.Result(0, false, "");
        CommandExecutor fake = new CommandExecutor() {
            @Override
            public Result exec(List<String> argv, java.time.Duration timeout) {
                return exec(argv, Map.of(), timeout);
            }

            @Override
            public Result exec(List<String> argv, Map<String, String> env, java.time.Duration timeout) {
                dockerCalls.add(argv);
                if (argv.contains("run")) {
                    lastEnv = env;
                    duringTool.run();
                    for (String a : argv) {
                        if (a.startsWith("type=bind,source=")) {
                            String src = a.substring("type=bind,source=".length(), a.indexOf(",target="));
                            Path dir = Path.of(src);
                            // what a container would see at this moment
                            try (var files = Files.list(dir)) {
                                filesDuringRun = files.map(p -> p.getFileName().toString()).toList();
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }
                            if (secretFileContent == null && Files.exists(dir.resolve("auth-headers.txt"))) {
                                try { secretFileContent = Files.readString(dir.resolve("auth-headers.txt")); }
                                catch (IOException e) { throw new RuntimeException(e); }
                            }
                            toolBehaviour.accept(dir);
                        }
                    }
                }
                return toolResult;
            }
        };

        target = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tester");
        auth = new Authorization("a1", "e1", "tester");
        gateAllows();

        retests = mock(RetestRepository.class);
        credentials = mock(CredentialService.class);
        executor = new ScanExecutor(gate, new ScannerRegistry(List.of(new NucleiAdapter(new AppProperties()), new ZapAdapter(),
                new ZapApiAdapter(), new TestsslAdapter(), new NmapAdapter())), new DockerRunner(fake, props),
                scanRuns, findings, retests, credentials, audit,
                props, settings, new TransactionTemplate(mock(PlatformTransactionManager.class)));
    }

    private Map<String, String> lastEnv = Map.of();
    private List<String> filesDuringRun = List.of();
    private String secretFileContent;
    private RetestRepository retests;
    private CredentialService credentials;

    private static void write(Path dir, String name, String content) {
        try {
            Files.writeString(dir.resolve(name), content);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void gateAllows() {
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(
                new AuthorizationGateService.GateResult(true, null, auth, target, List.of("93.184.216.34")));
    }

    private ScanRun queued(String tool, ScanCategory category, ScanMode mode) {
        ScanRun r = new ScanRun(RUN, "e1", "a1", null, "app.example.com", mode, tool);
        r.setTargetId("t1");
        r.setCategory(category);
        r.setStatus(ScanStatus.RUNNING); // the worker has claimed it
        runs.put(RUN, r);
        return r;
    }

    @Test
    void successfulRunStoresFindingsWithFixAdviceAndCompletes() {
        ScanRun run = queued("nuclei", ScanCategory.WEB, ScanMode.PASSIVE);
        executor.execute(RUN);

        assertEquals(ScanStatus.COMPLETED, run.getStatus());
        assertEquals(1, run.getFindingCount());
        assertEquals(0, run.getExitCode());
        assertEquals(1, savedFindings.size());
        Finding f = savedFindings.get(0);
        assertEquals("Git Config Exposure", f.getTitle());
        assertEquals(Severity.MEDIUM, f.getSeverity());
        assertEquals("nuclei", f.getTool());
        assertEquals("t1", f.getTargetId());
        assertNotNull(f.getRemediation());
        assertNotNull(f.getFingerprint());
    }

    @Test
    void theDockerCommandIsPinnedToTheGateApprovedAddressAndUsesTheScanNetwork() {
        queued("nuclei", ScanCategory.WEB, ScanMode.PASSIVE);
        executor.execute(RUN);

        List<String> argv = dockerCalls.get(0);
        assertEquals("app.example.com:93.184.216.34", argv.get(argv.indexOf("--add-host") + 1));
        assertEquals("sentinelops-scan", argv.get(argv.indexOf("--network") + 1));
        assertTrue(argv.contains("no-new-privileges"));
    }

    @Test
    void labTargetsAreScannedOnTheLabNetworkOnlyAndNotPinned() {
        target.setLab(true);
        target.setBaseUrl("http://app.example.com:3000");
        queued("nuclei", ScanCategory.WEB, ScanMode.PASSIVE);
        executor.execute(RUN);

        List<String> argv = dockerCalls.get(0);
        assertEquals("sentinelops-lab", argv.get(argv.indexOf("--network") + 1));
        assertFalse(argv.contains("--add-host"));
    }

    @Test
    void theSameIssueFoundAgainIsNotDuplicated() {
        queued("nuclei", ScanCategory.WEB, ScanMode.PASSIVE);
        executor.execute(RUN);
        ScanRun again = queued("nuclei", ScanCategory.WEB, ScanMode.PASSIVE);
        executor.execute(RUN);
        assertEquals(ScanStatus.COMPLETED, again.getStatus());
        assertEquals(1, savedFindings.size(), "same target + tool + rule + location = one finding");
        assertNotNull(savedFindings.get(0).getLastSeenAt());
    }

    @Test
    void gateDeniedAtExecutionNeverStartsAContainer() {
        ScanRun run = queued("nuclei", ScanCategory.WEB, ScanMode.PASSIVE);
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(
                new AuthorizationGateService.GateResult(false, "Authorization has expired.", null, target, List.of()));
        executor.execute(RUN);

        assertEquals(ScanStatus.FAILED, run.getStatus());
        assertTrue(run.getError().startsWith("Gate denied at execution"));
        assertTrue(dockerCalls.isEmpty());
    }

    @Test
    void activeRunIsDowngradedWhenTheGlobalSwitchWasTurnedOffMeanwhile() {
        auth.setAllowActive(true);
        when(settings.isActiveScanningEnabled()).thenReturn(false);
        ScanRun run = queued("zap", ScanCategory.WEB, ScanMode.ACTIVE);
        toolBehaviour = dir -> write(dir, "zap.json", "{\"site\":[]}");
        executor.execute(RUN);

        assertEquals(ScanMode.PASSIVE, run.getMode());
        assertTrue(dockerCalls.get(0).contains("zap-baseline.py"));
        assertFalse(dockerCalls.get(0).contains("zap-full-scan.py"));
    }

    @Test
    void toolFailureAndTimeoutEndTheRunFailedWithAReason() {
        ScanRun run = queued("zap", ScanCategory.WEB, ScanMode.PASSIVE);
        toolResult = new CommandExecutor.Result(3, false, "ZAP could not start");
        executor.execute(RUN);
        assertEquals(ScanStatus.FAILED, run.getStatus());
        assertTrue(run.getError().contains("code 3"));

        run = queued("zap", ScanCategory.WEB, ScanMode.PASSIVE);
        toolResult = new CommandExecutor.Result(-1, true, "");
        executor.execute(RUN);
        assertEquals(ScanStatus.FAILED, run.getStatus());
        assertTrue(run.getError().startsWith("Timed out"));
        assertTrue(dockerCalls.stream().anyMatch(c -> c.contains("rm")), "container removed after a timeout");
    }

    @Test
    void missingOrBrokenOutputIsAFailureNeverAnEmptySuccess() {
        ScanRun run = queued("zap", ScanCategory.WEB, ScanMode.PASSIVE);
        toolBehaviour = dir -> {}; // tool "succeeded" but wrote nothing
        executor.execute(RUN);
        assertEquals(ScanStatus.FAILED, run.getStatus());
        assertTrue(savedFindings.isEmpty());
    }

    @Test
    void aStopRequestWinsOverWhateverTheToolProduced() {
        ScanRun run = queued("nuclei", ScanCategory.WEB, ScanMode.PASSIVE);
        duringTool = () -> run.setStatus(ScanStatus.STOPPED);
        executor.execute(RUN);

        assertEquals(ScanStatus.STOPPED, run.getStatus());
        assertTrue(savedFindings.isEmpty());
    }

    @Test
    void aRunThatIsNotRunningIsIgnored() {
        ScanRun run = queued("nuclei", ScanCategory.WEB, ScanMode.PASSIVE);
        run.setStatus(ScanStatus.QUEUED);
        executor.execute(RUN);
        assertEquals(ScanStatus.QUEUED, run.getStatus());
        assertTrue(dockerCalls.isEmpty());
        verify(gate, never()).evaluate(any(), any(), any(), any());
    }

    @Test
    void zapFindingsAreIdentifiedByRuleNotByWhichUrlsTheSpiderReached() {
        var a = new NormalizedFinding("10038", "CSP", Severity.MEDIUM, "https://x/a", null, null, null);
        var b = new NormalizedFinding("10038", "CSP", Severity.MEDIUM, "https://x/a https://x/b", null, null, null);
        assertEquals(ScanExecutor.fingerprint("t1", "zap", a), ScanExecutor.fingerprint("t1", "zap", b));
        assertNotEquals(ScanExecutor.fingerprint("t1", "nuclei", a), ScanExecutor.fingerprint("t1", "nuclei", b));
        assertNotEquals(ScanExecutor.fingerprint("t1", "zap", a), ScanExecutor.fingerprint("t2", "zap", a));
    }

    // ---------------- Phase 4: retests ----------------

    private void stubFindingLookup() {
        when(findings.findByTargetIdAndToolAndStatus(any(), any(), any())).thenAnswer(i ->
                savedFindings.stream().filter(f -> Objects.equals(f.getTargetId(), i.getArgument(0))
                        && Objects.equals(f.getTool(), i.getArgument(1)) && f.getStatus() == i.getArgument(2)).toList());
    }

    private Finding existing(String rule, String location, FindingStatus status, ScanMode foundMode) {
        var n = new NormalizedFinding(rule, "Old", Severity.MEDIUM, location, null, null, null);
        Finding f = new Finding(UUID.randomUUID().toString(), "e1", "old-run", null, "Old", Severity.MEDIUM);
        f.setTargetId("t1");
        f.setTool("nuclei");
        f.setFingerprint(ScanExecutor.fingerprint("t1", "nuclei", n));
        f.setStatus(status);
        f.setFoundMode(foundMode);
        savedFindings.add(f);
        return f;
    }

    @Test
    void aFixedFindingNoLongerSeenPassesTheRetest() {
        stubFindingLookup();
        Finding old = existing("other-rule", "https://app.example.com/old", FindingStatus.FIXED, ScanMode.PASSIVE);
        queued("nuclei", ScanCategory.WEB, ScanMode.PASSIVE);
        executor.execute(RUN);

        assertEquals(FindingStatus.RETEST_PASS, old.getStatus());
        verify(retests).save(argThat(r -> r.getFindingId().equals(old.getId()) && r.getResult().equals("PASS")));
    }

    @Test
    void aFixedFindingStillSeenFailsTheRetestAndIsNotDuplicated() {
        stubFindingLookup();
        Finding old = existing("git-config", "https://app.example.com/.git/config", FindingStatus.FIXED, ScanMode.PASSIVE);
        queued("nuclei", ScanCategory.WEB, ScanMode.PASSIVE);
        executor.execute(RUN);

        assertEquals(FindingStatus.RETEST_FAIL, old.getStatus());
        verify(retests).save(argThat(r -> r.getResult().equals("FAIL")));
        assertEquals(1, savedFindings.size());
    }

    @Test
    void aPassiveRunCannotProveAnActiveFindingFixed() {
        stubFindingLookup();
        Finding old = existing("other-rule", "x", FindingStatus.FIXED, ScanMode.ACTIVE);
        queued("nuclei", ScanCategory.WEB, ScanMode.PASSIVE);
        executor.execute(RUN);

        assertEquals(FindingStatus.FIXED, old.getStatus(), "stays FIXED, no conclusion");
        verify(retests, never()).save(any());
    }

    @Test
    void aFailedRunNeverSettlesARetest() {
        stubFindingLookup();
        Finding old = existing("other-rule", "x", FindingStatus.FIXED, ScanMode.PASSIVE);
        queued("nuclei", ScanCategory.WEB, ScanMode.PASSIVE);
        toolResult = new CommandExecutor.Result(2, false, "boom");
        executor.execute(RUN);

        assertEquals(FindingStatus.FIXED, old.getStatus(), "a scan that did not run proves nothing");
        verify(retests, never()).save(any());
    }

    @Test
    void aClosedFindingThatComesBackIsReopened() {
        Finding old = existing("git-config", "https://app.example.com/.git/config", FindingStatus.CLOSED, ScanMode.PASSIVE);
        queued("nuclei", ScanCategory.WEB, ScanMode.PASSIVE);
        executor.execute(RUN);
        assertEquals(FindingStatus.OPEN, old.getStatus());
    }

    @Test
    void newFindingsRememberTheModeTheyWereFoundIn() {
        queued("nuclei", ScanCategory.WEB, ScanMode.PASSIVE);
        executor.execute(RUN);
        assertEquals(ScanMode.PASSIVE, savedFindings.get(0).getFoundMode());
        assertFalse(savedFindings.get(0).isValidated(), "scanner output is a candidate until a tester confirms it");
    }

    // ---------------- Phase 5: authenticated scans, OpenAPI ----------------

    private static final String SECRET = "Bearer s3cr3t-token-123";

    @Test
    void credentialIsUsedOnlyWhenTheAuthorizationAllowsAuthenticatedScans() {
        when(credentials.decrypt("t1")).thenReturn(Optional.of(new CredentialService.Header("Authorization", SECRET)));
        queued("nuclei", ScanCategory.WEB, ScanMode.PASSIVE);
        executor.execute(RUN);
        verify(credentials, never()).decrypt(any());
        assertNull(secretFileContent);
    }

    @Test
    void nucleiGetsTheCredentialFromAFileThatExistsOnlyDuringTheRun() throws Exception {
        auth.setAllowAuthenticated(true);
        when(credentials.decrypt("t1")).thenReturn(Optional.of(new CredentialService.Header("Authorization", SECRET)));
        ScanRun run = queued("nuclei", ScanCategory.WEB, ScanMode.PASSIVE);
        executor.execute(RUN);

        assertEquals(ScanStatus.COMPLETED, run.getStatus());
        assertEquals("Authorization: " + SECRET + "\n", secretFileContent);
        assertTrue(filesDuringRun.contains("auth-headers.txt"));
        assertFalse(Files.exists(work.resolve(RUN).resolve("auth-headers.txt")), "secret file removed after the run");
        for (List<String> argv : dockerCalls) {
            assertTrue(argv.stream().noneMatch(a -> a.contains("s3cr3t")), "the secret is never in a command line");
        }
    }

    @Test
    void zapGetsTheCredentialThroughTheEnvironmentNotTheCommandLine() {
        auth.setAllowAuthenticated(true);
        when(credentials.decrypt("t1")).thenReturn(Optional.of(new CredentialService.Header("Authorization", SECRET)));
        queued("zap", ScanCategory.WEB, ScanMode.PASSIVE);
        toolBehaviour = dir -> write(dir, "zap.json", "{\"site\":[]}");
        executor.execute(RUN);

        assertEquals(SECRET, lastEnv.get("ZAP_AUTH_HEADER_VALUE"));
        assertEquals("app.example.com", lastEnv.get("ZAP_AUTH_HEADER_SITE"));
        List<String> argv = dockerCalls.get(0);
        assertTrue(argv.contains("ZAP_AUTH_HEADER_VALUE"), "passed as '-e NAME' only");
        assertTrue(argv.stream().noneMatch(a -> a.contains("s3cr3t")));
    }

    @Test
    void credentialsAreNotUsedForTlsOrNetworkScans() {
        auth.setAllowAuthenticated(true);
        when(credentials.decrypt("t1")).thenReturn(Optional.of(new CredentialService.Header("Authorization", SECRET)));
        queued("nmap", ScanCategory.NETWORK, ScanMode.PASSIVE);
        toolBehaviour = dir -> write(dir, "nmap.xml", "<nmaprun/>");
        executor.execute(RUN);
        verify(credentials, never()).decrypt(any());
    }

    @Test
    void aCredentialNeverLeaksThroughToolOutputShownToUsers() {
        auth.setAllowAuthenticated(true);
        when(credentials.decrypt("t1")).thenReturn(Optional.of(new CredentialService.Header("Authorization", SECRET)));
        ScanRun run = queued("zap", ScanCategory.WEB, ScanMode.PASSIVE);
        toolResult = new CommandExecutor.Result(3, false, "request failed with header " + SECRET);
        executor.execute(RUN);

        assertEquals(ScanStatus.FAILED, run.getStatus());
        assertFalse(run.getError().contains("s3cr3t"));
        assertTrue(run.getError().contains("[hidden]"));
    }

    @Test
    void zapApiScanRunsOnlyInActiveModeWithAnImportedDefinition() {
        target.setOpenApiUrl("https://app.example.com/openapi.json");
        auth.setAllowActive(true);
        when(settings.isActiveScanningEnabled()).thenReturn(true);
        toolBehaviour = dir -> write(dir, "zap.json", "{\"site\":[]}");

        ScanRun run = queued("zap-api", ScanCategory.API, ScanMode.ACTIVE);
        executor.execute(RUN);
        assertEquals(ScanStatus.COMPLETED, run.getStatus(), String.valueOf(run.getError()));
        List<String> argv = dockerCalls.get(0);
        assertTrue(argv.contains("zap-api-scan.py"));
        assertEquals("app.example.com", argv.get(argv.indexOf("-O") + 1), "requests forced onto the authorized host");

        dockerCalls.clear();
        when(settings.isActiveScanningEnabled()).thenReturn(false); // switch turned off meanwhile -> downgraded
        ScanRun again = queued("zap-api", ScanCategory.API, ScanMode.ACTIVE);
        executor.execute(RUN);
        assertEquals(ScanStatus.FAILED, again.getStatus());
        assertTrue(dockerCalls.isEmpty());
    }
}
