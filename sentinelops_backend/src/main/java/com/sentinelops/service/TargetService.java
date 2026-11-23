package com.sentinelops.service;

import com.sentinelops.entity.*;
import com.sentinelops.repository.TargetRepository;
import com.sentinelops.util.CurrentUser;
import com.sentinelops.util.TargetParser;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/** Registers and lists targets. Registration never grants any permission to scan. */
@Service
public class TargetService {

    private final TargetRepository targets;
    private final ScopeValidator scope;
    private final AccessService access;
    private final AuditService audit;

    public TargetService(TargetRepository targets, ScopeValidator scope, AccessService access, AuditService audit) {
        this.targets = targets;
        this.scope = scope;
        this.access = access;
        this.audit = audit;
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public Target register(String engagementId, String value, String baseUrl, String label,
                           Technology technology, boolean lab, String actor) {
        Engagement engagement = access.requireEngagement(engagementId);
        if (lab && !CurrentUser.hasRole("ADMIN")) {
            throw new AccessDeniedException("Only an administrator can register a lab target.");
        }

        TargetParser.Parsed parsed = TargetParser.parse(value, lab);
        if (lab && parsed.kind() == TargetKind.CIDR) {
            throw new IllegalArgumentException("A lab target must be a single host or IP.");
        }
        if (targets.findByEngagementIdAndValue(engagement.getId(), parsed.value()).isPresent()) {
            throw new IllegalStateException("This target is already registered in the engagement.");
        }

        Target t = new Target(UUID.randomUUID().toString(), engagement.getId(), parsed.kind(), parsed.value(), actor);
        t.setLab(lab);
        t.setLabel(label);
        t.setTechnology(technology);
        if (baseUrl != null && !baseUrl.isBlank()) {
            String host = TargetParser.hostOfUrl(baseUrl);
            if (parsed.kind() == TargetKind.CIDR || !host.equals(parsed.value())) {
                throw new IllegalArgumentException("The base URL must use the target's own host.");
            }
            t.setBaseUrl(baseUrl.trim());
        }

        // Reject early what could never be scanned (private/loopback/metadata/server addresses, unresolvable names).
        ScopeValidator.Check check = scope.checkTarget(t);
        if (!check.allowed()) {
            audit.record(actor, "target.rejected", "Engagement", engagementId,
                    "value=" + parsed.value() + " reason=" + check.reason());
            throw new IllegalArgumentException("Target rejected: " + check.reason());
        }

        targets.save(t);
        audit.record(actor, "target.registered", "Target", t.getId(),
                "engagement=" + engagementId + " kind=" + t.getKind() + " value=" + t.getValue() + " lab=" + lab);
        return t;
    }

    @Transactional(readOnly = true)
    public List<Target> list(String engagementId) {
        access.requireEngagement(engagementId);
        return targets.findByEngagementIdOrderByCreatedAtAsc(engagementId);
    }

    @Transactional(readOnly = true)
    public Target get(String targetId) {
        return access.requireTarget(targetId);
    }
}
