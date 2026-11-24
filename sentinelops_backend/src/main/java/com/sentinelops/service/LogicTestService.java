package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.repository.ScanRunRepository;
import com.sentinelops.service.logic.AuthSessionChecks;
import com.sentinelops.service.logic.BusinessLogicChecks;
import com.sentinelops.service.logic.DefaultCredentialChecks;
import com.sentinelops.service.logic.DependencyChecks;
import com.sentinelops.service.logic.DnsHygieneChecks;
import com.sentinelops.service.logic.IdorChecks;
import com.sentinelops.service.logic.UploadChecks;
import com.sentinelops.service.scanner.NormalizedFinding;
import com.sentinelops.util.SecretBox;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * The logic-testing engine's run orchestrator (see PENTEST_COVERAGE_PLAN.md):
 *  - Phase 1 (A): auth/session checks (AUTH-11 JWT manipulation, AUTH-12 logout session reuse) for one
 *    stored test identity.
 *  - Phase 2 (D): the IDOR cross-access check (ACC-01 / ACC-05) for one stored probe pairing two identities.
 *
 * Both are gated more strictly than a plain scan, because they send genuinely intrusive traffic (forged
 * tokens, a real logout call, cross-account requests): the normal gate must allow WEB testing, AND the
 * signed authorization must allow both ACTIVE and authenticated testing, AND the admin's global
 * active-scanning switch must be on — the same conditions {@link ScanService#resolveMode} requires before
 * a real ACTIVE scan ever runs. Only confirmed-vulnerable results become Findings; "not vulnerable" and
 * "needs manual review" are returned to the caller but never stored as a finding.
 */
@Service
public class LogicTestService {

    public record CheckView(String checkId, String title, String verdict, String severity, String description) {
        static CheckView from(AuthSessionChecks.Result r) {
            return new CheckView(r.checkId(), r.title(), r.verdict().name(),
                    r.verdict() == AuthSessionChecks.Verdict.VULNERABLE ? r.severity().name() : null, r.description());
        }
        static CheckView fromIdor(IdorChecks.Result r) {
            return new CheckView(r.checkId(), r.title(), r.verdict().name(),
                    r.verdict() == IdorChecks.Verdict.VULNERABLE ? r.severity().name() : null, r.description());
        }
        static CheckView fromUpload(UploadChecks.Result r) {
            return new CheckView(r.checkId(), r.title(), r.verdict().name(),
                    r.verdict() == UploadChecks.Verdict.VULNERABLE ? r.severity().name() : null, r.description());
        }
        static CheckView fromBusiness(BusinessLogicChecks.Result r) {
            return new CheckView(r.checkId(), r.title(), r.verdict().name(),
                    r.verdict() == BusinessLogicChecks.Verdict.VULNERABLE ? r.severity().name() : null, r.description());
        }
        static CheckView fromDns(DnsHygieneChecks.Result r) {
            return new CheckView(r.checkId(), r.title(), r.verdict().name(),
                    r.verdict() == DnsHygieneChecks.Verdict.VULNERABLE ? r.severity().name() : null, r.description());
        }
        static CheckView fromDefaultCreds(DefaultCredentialChecks.Result r) {
            return new CheckView(r.checkId(), r.title(), r.verdict().name(),
                    r.verdict() == DefaultCredentialChecks.Verdict.VULNERABLE ? r.severity().name() : null, r.description());
        }
        /** npm's own advisory database already confirms these; every entry is reported, never a 3-state guess. */
        static CheckView fromDependency(NormalizedFinding f) {
            return new CheckView("npm-advisory", f.title(), "VULNERABLE", f.severity().name(), f.description());
        }
    }

    public record RunResult(String scanRunId, List<CheckView> checks, int vulnerableCount) {}

    /** Denies with a reason, or carries the gate's allowed result through to the caller. */
    private record Gate(AuthorizationGateService.GateResult result, String denyReason) {}

    private final TestIdentityService identityLookup;
    private final IdorProbeService idorProbes;
    private final UploadProbeService uploadProbes;
    private final BusinessLogicProbeService businessProbes;
    private final DependencyManifestService dependencyManifests;
    private final AuthorizationGateService gate;
    private final SettingsService settings;
    private final AuthSessionChecks authChecks;
    private final IdorChecks idorChecks;
    private final UploadChecks uploadChecks;
    private final BusinessLogicChecks businessChecks;
    private final DnsHygieneChecks dnsHygieneChecks;
    private final DefaultCredentialChecks defaultCredentialChecks;
    private final DependencyChecks dependencyChecks;
    private final ScanExecutor scanExecutor;
    private final ScanRunRepository scanRuns;
    private final AuditService audit;
    private final AppProperties props;

    public LogicTestService(TestIdentityService identityLookup, IdorProbeService idorProbes,
                            UploadProbeService uploadProbes, BusinessLogicProbeService businessProbes,
                            DependencyManifestService dependencyManifests, AuthorizationGateService gate,
                            SettingsService settings, AuthSessionChecks authChecks, IdorChecks idorChecks,
                            UploadChecks uploadChecks, BusinessLogicChecks businessChecks,
                            DnsHygieneChecks dnsHygieneChecks, DefaultCredentialChecks defaultCredentialChecks,
                            DependencyChecks dependencyChecks, ScanExecutor scanExecutor, ScanRunRepository scanRuns,
                            AuditService audit, AppProperties props) {
        this.identityLookup = identityLookup;
        this.idorProbes = idorProbes;
        this.uploadProbes = uploadProbes;
        this.businessProbes = businessProbes;
        this.dependencyManifests = dependencyManifests;
        this.gate = gate;
        this.settings = settings;
        this.authChecks = authChecks;
        this.idorChecks = idorChecks;
        this.uploadChecks = uploadChecks;
        this.businessChecks = businessChecks;
        this.dnsHygieneChecks = dnsHygieneChecks;
        this.defaultCredentialChecks = defaultCredentialChecks;
        this.dependencyChecks = dependencyChecks;
        this.scanExecutor = scanExecutor;
        this.scanRuns = scanRuns;
        this.audit = audit;
        this.props = props;
    }

    private Gate checkIntrusiveGate(String engagementId, String targetId) {
        var result = gate.evaluate(engagementId, targetId, ScanCategory.WEB, Instant.now());
        if (!result.allowed()) return new Gate(result, result.reason());
        if (!result.authorization().isAllowAuthenticated()) return new Gate(result, "the signed authorization does not allow authenticated testing.");
        if (!result.authorization().isAllowActive()) return new Gate(result, "the signed authorization does not allow ACTIVE testing.");
        if (!settings.isActiveScanningEnabled()) return new Gate(result, "active scanning is switched off (Settings).");
        return new Gate(result, null);
    }

    private ScanRun newRun(String engagementId, String targetId, String authorizationId, Target target,
                           List<String> addresses, String tool, ScanCategory category, ScanMode mode) {
        ScanRun run = new ScanRun(UUID.randomUUID().toString(), engagementId, authorizationId,
                target.getTechnology(), target.getValue(), mode, tool);
        run.setTargetId(targetId);
        run.setCategory(category);
        run.setPurpose("LOGIC_TEST");
        run.setResolvedAddresses(String.join(",", addresses));
        run.setStartedAt(Instant.now());
        return run;
    }

    private void finishRun(ScanRun run, Target target, String tool, ScanMode mode, List<NormalizedFinding> toRecord,
                           String actor, String auditAction, String auditDetail) {
        int added = scanExecutor.ingest(run, target, tool, mode, toRecord);
        run.setFindingCount(toRecord.size());
        run.setStatus(ScanStatus.COMPLETED);
        run.setEndedAt(Instant.now());
        scanRuns.save(run);
        audit.record(actor, auditAction, "Target", target.getId(), auditDetail + " new=" + added);
    }

    /** DNS checks reach no application endpoint at all, so they run under the plain (non-intrusive) gate. */
    private AuthorizationGateService.GateResult requirePassiveGate(String engagementId, String targetId,
                                                                   ScanCategory category, String actor,
                                                                   String auditAction, String auditDetail) {
        var result = gate.evaluate(engagementId, targetId, category, Instant.now());
        if (!result.allowed()) {
            audit.record(actor, auditAction, "Target", targetId, auditDetail + " denied: " + result.reason());
            throw new AccessDeniedException("Not permitted: " + result.reason());
        }
        return result;
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public RunResult runAuthChecks(String engagementId, String targetId, String identityId, String actor) {
        Target target = identityLookup.target(engagementId, targetId);
        TestIdentity identity = identityLookup.identity(targetId, identityId);

        var g = checkIntrusiveGate(engagementId, targetId);
        if (g.denyReason() != null) {
            audit.record(actor, "logic.auth_checks", "Target", targetId, "identity=" + identity.getLabel() + " denied: " + g.denyReason());
            throw new AccessDeniedException("Not permitted: " + g.denyReason());
        }

        String password = new SecretBox(props.getSecurity().getSecretKey()).decrypt(identity.getEncPassword());
        List<AuthSessionChecks.Result> raw = new ArrayList<>();
        raw.add(authChecks.checkLogoutSessionReuse(identity, password));
        raw.addAll(authChecks.checkJwt(identity, password));

        List<NormalizedFinding> toRecord = new ArrayList<>();
        for (var r : raw) {
            if (r.verdict() == AuthSessionChecks.Verdict.VULNERABLE) {
                toRecord.add(new NormalizedFinding("auth-" + r.checkId().toLowerCase(), r.title(), r.severity(),
                        identity.getLabel() + " @ " + r.location(), r.description(), r.remediation(), null));
            }
        }

        ScanRun run = newRun(engagementId, targetId, g.result().authorization().getId(), target, g.result().addresses(), "auth-logic", ScanCategory.WEB, ScanMode.ACTIVE);
        finishRun(run, target, "auth-logic", ScanMode.ACTIVE, toRecord, actor, "logic.auth_checks",
                "identity=" + identity.getLabel() + " checks=" + raw.size() + " vulnerable=" + toRecord.size());

        return new RunResult(run.getId(), raw.stream().map(CheckView::from).toList(), toRecord.size());
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public RunResult runIdorCheck(String engagementId, String targetId, String probeId, String actor) {
        Target target = identityLookup.target(engagementId, targetId);
        IdorProbe p = idorProbes.probe(targetId, probeId);
        TestIdentity a = identityLookup.identity(targetId, p.getIdentityAId());
        TestIdentity b = identityLookup.identity(targetId, p.getIdentityBId());

        var g = checkIntrusiveGate(engagementId, targetId);
        if (g.denyReason() != null) {
            audit.record(actor, "logic.idor_check", "Target", targetId, "probe=" + p.getLabel() + " denied: " + g.denyReason());
            throw new AccessDeniedException("Not permitted: " + g.denyReason());
        }

        SecretBox box = new SecretBox(props.getSecurity().getSecretKey());
        String pwA = box.decrypt(a.getEncPassword());
        String pwB = box.decrypt(b.getEncPassword());
        List<IdorChecks.Result> raw = idorChecks.checkCrossAccess(a, pwA, p.getResourceIdA(), b, pwB, p.getResourceIdB(), p.getUrlTemplate());

        List<NormalizedFinding> toRecord = new ArrayList<>();
        for (var r : raw) {
            if (r.verdict() == IdorChecks.Verdict.VULNERABLE) {
                toRecord.add(new NormalizedFinding("idor-" + r.checkId().toLowerCase(), r.title(), r.severity(),
                        p.getLabel() + " @ " + r.location(), r.description(), r.remediation(), null));
            }
        }

        ScanRun run = newRun(engagementId, targetId, g.result().authorization().getId(), target, g.result().addresses(), "idor-logic", ScanCategory.WEB, ScanMode.ACTIVE);
        finishRun(run, target, "idor-logic", ScanMode.ACTIVE, toRecord, actor, "logic.idor_check",
                "probe=" + p.getLabel() + " checks=" + raw.size() + " vulnerable=" + toRecord.size());

        return new RunResult(run.getId(), raw.stream().map(CheckView::fromIdor).toList(), toRecord.size());
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public RunResult runUploadCheck(String engagementId, String targetId, String probeId, String actor) {
        Target target = identityLookup.target(engagementId, targetId);
        UploadProbe p = uploadProbes.probe(targetId, probeId);
        TestIdentity identity = p.getIdentityId() == null ? null : identityLookup.identity(targetId, p.getIdentityId());

        var g = checkIntrusiveGate(engagementId, targetId);
        if (g.denyReason() != null) {
            audit.record(actor, "logic.upload_check", "Target", targetId, "probe=" + p.getLabel() + " denied: " + g.denyReason());
            throw new AccessDeniedException("Not permitted: " + g.denyReason());
        }

        String password = identity == null ? null : new SecretBox(props.getSecurity().getSecretKey()).decrypt(identity.getEncPassword());
        List<UploadChecks.Result> raw = uploadChecks.checkExtensionBypass(identity, password, p.getUploadUrl(),
                p.getFieldName(), p.getRetrievalUrlTemplate());

        List<NormalizedFinding> toRecord = new ArrayList<>();
        for (var r : raw) {
            if (r.verdict() == UploadChecks.Verdict.VULNERABLE) {
                toRecord.add(new NormalizedFinding("upload-" + r.checkId().toLowerCase(), r.title(), r.severity(),
                        p.getLabel() + " @ " + r.location(), r.description(), r.remediation(), null));
            }
        }

        ScanRun run = newRun(engagementId, targetId, g.result().authorization().getId(), target, g.result().addresses(), "upload-logic", ScanCategory.WEB, ScanMode.ACTIVE);
        finishRun(run, target, "upload-logic", ScanMode.ACTIVE, toRecord, actor, "logic.upload_check",
                "probe=" + p.getLabel() + " checks=" + raw.size() + " vulnerable=" + toRecord.size());

        return new RunResult(run.getId(), raw.stream().map(CheckView::fromUpload).toList(), toRecord.size());
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public RunResult runBusinessLogicCheck(String engagementId, String targetId, String probeId, String actor) {
        Target target = identityLookup.target(engagementId, targetId);
        BusinessLogicProbe p = businessProbes.probe(targetId, probeId);
        TestIdentity identity = p.getIdentityId() == null ? null : identityLookup.identity(targetId, p.getIdentityId());

        var g = checkIntrusiveGate(engagementId, targetId);
        if (g.denyReason() != null) {
            audit.record(actor, "logic.business_check", "Target", targetId, "probe=" + p.getLabel() + " denied: " + g.denyReason());
            throw new AccessDeniedException("Not permitted: " + g.denyReason());
        }

        String password = identity == null ? null : new SecretBox(props.getSecurity().getSecretKey()).decrypt(identity.getEncPassword());
        List<BusinessLogicChecks.Result> raw = businessChecks.checkAll(identity, password, p.getRequestUrl(),
                p.getHttpMethod(), p.getBodyTemplate(), p.getTamperedField(), p.getTamperedValue(), p.getConcurrency());

        List<NormalizedFinding> toRecord = new ArrayList<>();
        for (var r : raw) {
            if (r.verdict() == BusinessLogicChecks.Verdict.VULNERABLE) {
                toRecord.add(new NormalizedFinding("biz-" + r.checkId().toLowerCase(), r.title(), r.severity(),
                        p.getLabel() + " @ " + r.location(), r.description(), r.remediation(), null));
            }
        }

        ScanRun run = newRun(engagementId, targetId, g.result().authorization().getId(), target, g.result().addresses(), "biz-logic", ScanCategory.WEB, ScanMode.ACTIVE);
        finishRun(run, target, "biz-logic", ScanMode.ACTIVE, toRecord, actor, "logic.business_check",
                "probe=" + p.getLabel() + " checks=" + raw.size() + " vulnerable=" + toRecord.size());

        return new RunResult(run.getId(), raw.stream().map(CheckView::fromBusiness).toList(), toRecord.size());
    }

    /** Phase 5 (NET-09): SPF/DMARC hygiene. Passive - only DNS is read, nothing is sent to the target's app. */
    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public RunResult runDnsHygieneCheck(String engagementId, String targetId, String actor) {
        Target target = identityLookup.target(engagementId, targetId);
        if (target.getKind() != TargetKind.DOMAIN) {
            throw new IllegalArgumentException("DNS hygiene checks need a domain target, not an IP or range.");
        }
        var result = requirePassiveGate(engagementId, targetId, ScanCategory.NETWORK, actor,
                "logic.dns_hygiene", "domain=" + target.getValue());

        List<DnsHygieneChecks.Result> raw = dnsHygieneChecks.check(target.getValue());
        List<NormalizedFinding> toRecord = new ArrayList<>();
        for (var r : raw) {
            if (r.verdict() == DnsHygieneChecks.Verdict.VULNERABLE) {
                toRecord.add(new NormalizedFinding("dns-" + r.checkId().toLowerCase(), r.title(), r.severity(),
                        r.location(), r.description(), r.remediation(), null));
            }
        }

        ScanRun run = newRun(engagementId, targetId, result.authorization().getId(), target, result.addresses(),
                "dns-hygiene", ScanCategory.NETWORK, ScanMode.PASSIVE);
        finishRun(run, target, "dns-hygiene", ScanMode.PASSIVE, toRecord, actor, "logic.dns_hygiene",
                "domain=" + target.getValue() + " checks=" + raw.size() + " vulnerable=" + toRecord.size());

        return new RunResult(run.getId(), raw.stream().map(CheckView::fromDns).toList(), toRecord.size());
    }

    /**
     * Phase 5 (NET-07): tries a short list of well-known default credential pairs against an existing test
     * identity's login shape (its OWN stored username/password are ignored). Gated like the other intrusive
     * checks, because this sends real login attempts.
     */
    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public RunResult runDefaultCredentialCheck(String engagementId, String targetId, String identityId, String actor) {
        Target target = identityLookup.target(engagementId, targetId);
        TestIdentity shape = identityLookup.identity(targetId, identityId);

        var g = checkIntrusiveGate(engagementId, targetId);
        if (g.denyReason() != null) {
            audit.record(actor, "logic.default_creds", "Target", targetId, "identity=" + shape.getLabel() + " denied: " + g.denyReason());
            throw new AccessDeniedException("Not permitted: " + g.denyReason());
        }

        DefaultCredentialChecks.Result r = defaultCredentialChecks.check(shape);
        List<NormalizedFinding> toRecord = new ArrayList<>();
        if (r.verdict() == DefaultCredentialChecks.Verdict.VULNERABLE) {
            toRecord.add(new NormalizedFinding("net-" + r.checkId().toLowerCase(), r.title(), r.severity(),
                    shape.getLabel() + " @ " + r.location(), r.description(), r.remediation(), null));
        }

        ScanRun run = newRun(engagementId, targetId, g.result().authorization().getId(), target, g.result().addresses(),
                "default-creds", ScanCategory.WEB, ScanMode.ACTIVE);
        finishRun(run, target, "default-creds", ScanMode.ACTIVE, toRecord, actor, "logic.default_creds",
                "identity=" + shape.getLabel() + " vulnerable=" + toRecord.size());

        return new RunResult(run.getId(), List.of(CheckView.fromDefaultCreds(r)), toRecord.size());
    }

    /**
     * Phase 6 (L: dependency / SCA scanning): runs "npm audit" against an uploaded package-lock.json. This
     * never touches the target's own infrastructure - only the public npm registry's advisory data - so it
     * runs under the plain non-intrusive gate (WEB category), the same as the DNS hygiene check.
     */
    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public RunResult runDependencyCheck(String engagementId, String targetId, String manifestId, String actor) {
        Target target = dependencyManifests.target(engagementId, targetId);
        DependencyManifest m = dependencyManifests.manifest(targetId, manifestId);

        var result = requirePassiveGate(engagementId, targetId, ScanCategory.WEB, actor,
                "logic.dependency_check", "manifest=" + m.getLabel());

        List<NormalizedFinding> toRecord;
        try {
            toRecord = dependencyChecks.check(m.getManifestContent());
        } catch (Exception ex) {
            audit.record(actor, "logic.dependency_check", "Target", targetId,
                    "manifest=" + m.getLabel() + " failed: " + ex.getClass().getSimpleName());
            throw new IllegalStateException("The dependency scan could not run: " + ex.getClass().getSimpleName()
                    + ". Check that npm is installed on the server.");
        }

        ScanRun run = newRun(engagementId, targetId, result.authorization().getId(), target, result.addresses(),
                "dependency-scan", ScanCategory.WEB, ScanMode.PASSIVE);
        finishRun(run, target, "dependency-scan", ScanMode.PASSIVE, toRecord, actor, "logic.dependency_check",
                "manifest=" + m.getLabel() + " findings=" + toRecord.size());

        return new RunResult(run.getId(), toRecord.stream().map(CheckView::fromDependency).toList(), toRecord.size());
    }
}
