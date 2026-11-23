package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.repository.TargetRepository;
import com.sentinelops.repository.TargetVerificationRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Ownership verification of targets.
 *  - DOMAIN: DNS TXT record or an HTTP file carrying a unique, time-limited token.
 *  - IP / CIDR: a recorded manual approval (system owner + network-team acknowledgement + evidence).
 * Verification is repeatable and expires; it is NOT permission to test (see the authorization gate).
 */
@Service
public class VerificationService {

    public static final String DNS_PREFIX = "_sentinelops-challenge.";
    public static final String DNS_VALUE_PREFIX = "sentinelops-verify=";
    public static final String HTTP_PATH = "/.well-known/sentinelops-verify.txt";

    public record Instructions(String recordName, String recordValue, String fileUrl, String fileContent) {}
    public record ChallengeView(TargetVerification verification, Instructions instructions) {}

    private static final SecureRandom RANDOM = new SecureRandom();

    private final TargetVerificationRepository verifications;
    private final TargetRepository targets;
    private final ScopeValidator scope;
    private final TxtLookup txt;
    private final HttpTokenFetcher http;
    private final AuditService audit;
    private final AccessService access;
    private final AppProperties props;

    public VerificationService(TargetVerificationRepository verifications, TargetRepository targets,
                               ScopeValidator scope, TxtLookup txt, HttpTokenFetcher http,
                               AuditService audit, AccessService access, AppProperties props) {
        this.verifications = verifications;
        this.targets = targets;
        this.scope = scope;
        this.txt = txt;
        this.http = http;
        this.audit = audit;
        this.access = access;
        this.props = props;
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public ChallengeView start(String targetId, VerificationMethod method, String actor) {
        Target target = access.requireTarget(targetId);
        if (target.getKind() != TargetKind.DOMAIN || method == VerificationMethod.MANUAL) {
            throw new IllegalArgumentException(
                    "Domains are verified with DNS_TXT or HTTP_FILE. IPs and ranges need a manual approval record.");
        }
        if (target.isLab()) {
            throw new IllegalArgumentException("Lab targets do not use ownership verification.");
        }
        expirePending(targetId);

        String token = randomToken();
        Instant now = Instant.now();
        TargetVerification v = new TargetVerification(UUID.randomUUID().toString(), targetId, method, token,
                now.plus(Duration.ofHours(props.getVerification().getChallengeHours())), actor);
        verifications.save(v);
        audit.record(actor, "target.verification.started", "Target", targetId,
                "method=" + method + " expires=" + v.getExpiresAt());
        return new ChallengeView(v, instructionsFor(target, v));
    }

    /** Checks the latest pending challenge right now. Safe to call repeatedly. */
    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public ChallengeView check(String targetId, String actor) {
        Target target = access.requireTarget(targetId);
        TargetVerification v = verifications
                .findFirstByTargetIdAndStatusOrderByCreatedAtDesc(targetId, ChallengeStatus.PENDING)
                .orElseThrow(() -> new IllegalStateException("No pending challenge. Start a verification first."));
        Instant now = Instant.now();
        v.setLastCheckedAt(now);

        if (!v.getExpiresAt().isAfter(now)) {
            v.setStatus(ChallengeStatus.EXPIRED);
            v.setDetail("Challenge token expired. Start a new verification.");
            verifications.save(v);
            audit.record(actor, "target.verification.expired", "Target", targetId, "method=" + v.getMethod());
            return new ChallengeView(v, instructionsFor(target, v));
        }

        boolean ok;
        String detail;
        try {
            if (v.getMethod() == VerificationMethod.DNS_TXT) {
                String name = DNS_PREFIX + target.getValue();
                List<String> records = txt.lookup(name);
                String expected = DNS_VALUE_PREFIX + v.getToken();
                ok = records.stream().anyMatch(r -> r.trim().equals(expected));
                detail = ok ? "TXT record found." : "TXT record not found at " + name + " (" + records.size() + " record(s) seen).";
            } else {
                // SSRF guard: never connect to a host that resolves to a forbidden address.
                ScopeValidator.Check sc = scope.checkTarget(target);
                if (!sc.allowed()) {
                    ok = false;
                    detail = "Refused: " + sc.reason();
                } else {
                    ok = false;
                    detail = "Verification file not found or token mismatch.";
                    for (String scheme : new String[]{"https://", "http://"}) {
                        Optional<String> body = fetchQuietly(scheme + target.getValue() + HTTP_PATH);
                        if (body.isPresent() && body.get().equals(v.getToken())) {
                            ok = true;
                            detail = "Verification file found over " + scheme.replace("://", "") + ".";
                            break;
                        }
                    }
                }
            }
        } catch (Exception e) {
            ok = false;
            detail = "Check failed: " + e.getClass().getSimpleName();
        }

        v.setDetail(detail);
        if (ok) {
            v.setStatus(ChallengeStatus.VERIFIED);
            v.setVerifiedAt(now);
            markTargetVerified(target, now);
            audit.record(actor, "target.verified", "Target", targetId, "method=" + v.getMethod());
        } else {
            audit.record(actor, "target.verification.failed", "Target", targetId,
                    "method=" + v.getMethod() + " detail=" + detail);
        }
        verifications.save(v);
        return new ChallengeView(v, instructionsFor(target, v));
    }

    /** IP / CIDR ownership: recorded approval by the system owner plus network-team acknowledgement. */
    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    @Transactional
    public TargetVerification recordManualApproval(String targetId, String approverName, String approverContact,
                                                   String networkAckBy, String evidenceRef, String notes,
                                                   String actor) {
        Target target = access.requireTarget(targetId);
        if (target.getKind() == TargetKind.DOMAIN) {
            throw new IllegalArgumentException("Domains must be verified through DNS_TXT or HTTP_FILE.");
        }
        if (target.isLab()) {
            throw new IllegalArgumentException("Lab targets do not use ownership verification.");
        }
        expirePending(targetId);
        Instant now = Instant.now();
        TargetVerification v = new TargetVerification(UUID.randomUUID().toString(), targetId,
                VerificationMethod.MANUAL, null, now, actor);
        v.setStatus(ChallengeStatus.VERIFIED);
        v.setVerifiedAt(now);
        v.setApproverName(approverName);
        v.setApproverContact(approverContact);
        v.setNetworkAckBy(networkAckBy);
        v.setNetworkAckAt(now);
        v.setEvidenceRef(evidenceRef);
        v.setDetail(notes);
        verifications.save(v);
        markTargetVerified(target, now);
        audit.record(actor, "target.verified", "Target", targetId,
                "method=MANUAL owner=" + approverName + " networkAck=" + networkAckBy + " evidence=" + evidenceRef);
        return v;
    }

    @Transactional(readOnly = true)
    public List<TargetVerification> history(String targetId) {
        access.requireTarget(targetId);
        return verifications.findByTargetIdOrderByCreatedAtDesc(targetId);
    }

    private Optional<String> fetchQuietly(String url) {
        try {
            return http.fetch(url);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private void expirePending(String targetId) {
        for (TargetVerification old : verifications.findByTargetIdAndStatus(targetId, ChallengeStatus.PENDING)) {
            old.setStatus(ChallengeStatus.EXPIRED);
            old.setDetail("Superseded by a newer challenge.");
            verifications.save(old);
        }
    }

    private void markTargetVerified(Target target, Instant now) {
        target.setVerificationStatus(TargetStatus.VERIFIED);
        target.setVerifiedAt(now);
        target.setVerificationExpiresAt(now.plus(Duration.ofDays(props.getVerification().getValidDays())));
        targets.save(target);
    }

    private static String randomToken() {
        byte[] b = new byte[24];
        RANDOM.nextBytes(b);
        return HexFormat.of().formatHex(b);
    }

    static Instructions instructionsFor(Target target, TargetVerification v) {
        if (v.getMethod() == VerificationMethod.DNS_TXT) {
            return new Instructions(DNS_PREFIX + target.getValue(), DNS_VALUE_PREFIX + v.getToken(), null, null);
        }
        if (v.getMethod() == VerificationMethod.HTTP_FILE) {
            return new Instructions(null, null, "http(s)://" + target.getValue() + HTTP_PATH, v.getToken());
        }
        return new Instructions(null, null, null, null);
    }
}
