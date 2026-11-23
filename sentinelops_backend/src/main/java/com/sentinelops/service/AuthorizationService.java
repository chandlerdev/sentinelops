package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.exception.NotFoundException;
import com.sentinelops.repository.AuthorizationRepository;
import com.sentinelops.repository.EngagementRepository;
import com.sentinelops.repository.TargetRepository;
import com.sentinelops.util.TargetParser;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Written-authorization workflow: DRAFT -> PENDING_APPROVAL -> SIGNED | REJECTED, SIGNED -> REVOKED.
 * A tester proposes; a manager/admin approves (a different person from the requester when four-eyes is on).
 * Approval is refused while any covered target is unverified.
 */
@Service
public class AuthorizationService {

    private final AuthorizationRepository authorizations;
    private final EngagementRepository engagements;
    private final TargetRepository targets;
    private final AccessService access;
    private final AuditService audit;
    private final AppProperties props;

    public AuthorizationService(AuthorizationRepository authorizations, EngagementRepository engagements,
                                TargetRepository targets, AccessService access, AuditService audit,
                                AppProperties props) {
        this.authorizations = authorizations;
        this.engagements = engagements;
        this.targets = targets;
        this.access = access;
        this.audit = audit;
        this.props = props;
    }

    public record Draft(String title, String approverName, String approverContact, String emergencyContact,
                        Collection<ScanCategory> permittedMethods, Collection<String> excludedAssets,
                        Instant windowStart, Instant windowEnd, boolean allowActive, String evidenceRef,
                        Collection<String> targetIds, boolean allowAuthenticated) {
        public Draft(String title, String approverName, String approverContact, String emergencyContact,
                     Collection<ScanCategory> permittedMethods, Collection<String> excludedAssets,
                     Instant windowStart, Instant windowEnd, boolean allowActive, String evidenceRef,
                     Collection<String> targetIds) {
            this(title, approverName, approverContact, emergencyContact, permittedMethods, excludedAssets,
                    windowStart, windowEnd, allowActive, evidenceRef, targetIds, false);
        }
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public Authorization create(String engagementId, Draft d, String actor) {
        Engagement engagement = access.requireEngagement(engagementId);
        Instant now = Instant.now();

        if (d.permittedMethods() == null || d.permittedMethods().isEmpty()) {
            throw new IllegalArgumentException("At least one permitted testing method is required.");
        }
        if (d.targetIds() == null || d.targetIds().isEmpty()) {
            throw new IllegalArgumentException("At least one target must be in scope.");
        }
        if (d.windowStart() == null || d.windowEnd() == null || !d.windowEnd().isAfter(d.windowStart())) {
            throw new IllegalArgumentException("The testing window end must be after its start.");
        }
        if (!d.windowEnd().isAfter(now)) {
            throw new IllegalArgumentException("The testing window must end in the future.");
        }
        if (Duration.between(d.windowStart(), d.windowEnd()).toDays() > props.getSecurity().getMaxWindowDays()) {
            throw new IllegalArgumentException("The testing window may not exceed "
                    + props.getSecurity().getMaxWindowDays() + " days.");
        }
        if (d.excludedAssets() != null) {
            for (String ex : d.excludedAssets()) {
                TargetParser.parse(ex, true); // throws IllegalArgumentException when not a domain / IP / CIDR
            }
        }

        Authorization a = new Authorization(UUID.randomUUID().toString(), engagement.getId(), actor);
        a.setTitle(d.title());
        a.setApproverName(d.approverName());
        a.setApproverContact(d.approverContact());
        a.setEmergencyContact(d.emergencyContact());
        a.setPermittedMethodSet(d.permittedMethods());
        a.setExcludedAssetList(d.excludedAssets());
        a.setWindowStart(d.windowStart());
        a.setWindowEnd(d.windowEnd());
        a.setExpiresAt(d.windowEnd());
        a.setAllowActive(d.allowActive());
        a.setAllowAuthenticated(d.allowAuthenticated());
        a.setRoeReference(d.evidenceRef());
        for (String tid : d.targetIds()) {
            Target t = targets.findById(tid).orElseThrow(() -> new NotFoundException("Target not found: " + tid));
            if (!t.getEngagementId().equals(engagement.getId())) {
                throw new IllegalArgumentException("Target " + tid + " belongs to a different engagement.");
            }
            a.getTargetIds().add(tid);
        }
        authorizations.save(a);
        audit.record(actor, "authorization.created", "Authorization", a.getId(),
                "engagement=" + engagementId + " targets=" + a.getTargetIds().size()
                        + " methods=" + a.getPermittedMethodSet() + " active=" + a.isAllowActive());
        return a;
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public Authorization submit(String authorizationId, String actor) {
        Authorization a = load(authorizationId);
        if (a.getStatus() != AuthStatus.DRAFT) {
            throw new IllegalStateException("Only a draft can be submitted (current: " + a.getStatus() + ").");
        }
        a.setStatus(AuthStatus.PENDING_APPROVAL);
        authorizations.save(a);
        audit.record(actor, "authorization.submitted", "Authorization", a.getId(), null);
        return a;
    }

    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    @Transactional
    public Authorization approve(String authorizationId, String note, String actor) {
        Authorization a = load(authorizationId);
        if (a.getStatus() != AuthStatus.PENDING_APPROVAL) {
            throw new IllegalStateException("Only a pending authorization can be approved (current: " + a.getStatus() + ").");
        }
        if (props.getSecurity().isFourEyes() && actor.equalsIgnoreCase(a.getRequestedBy())) {
            throw new AccessDeniedException("The approver must be a different person from the requester.");
        }
        Instant now = Instant.now();
        if (a.getWindowEnd() == null || !a.getWindowEnd().isAfter(now)) {
            throw new IllegalStateException("The testing window has already ended.");
        }
        for (String tid : a.getTargetIds()) {
            Target t = targets.findById(tid).orElseThrow(() -> new NotFoundException("Target not found"));
            if (!t.isOwnershipEstablishedAt(now)) {
                throw new IllegalStateException("Target '" + t.getValue() + "' is not verified; verify ownership first.");
            }
        }
        a.setStatus(AuthStatus.SIGNED);
        a.setSignedBy(a.getApproverName());
        a.setSignedAt(now);
        a.setApprovedBy(actor);
        a.setApprovedAt(now);
        a.setDecisionNote(note);
        authorizations.save(a);

        Engagement e = engagements.findById(a.getEngagementId()).orElse(null);
        if (e != null && e.getState() == TicketState.AWAITING_AUTHORIZATION) {
            StateMachine.assertTransition(TicketState.AWAITING_AUTHORIZATION, TicketState.AUTHORIZED);
            e.setState(TicketState.AUTHORIZED);
            engagements.save(e);
        }
        audit.record(actor, "authorization.approved", "Authorization", a.getId(),
                "signedBy=" + a.getSignedBy() + " window=" + a.getWindowStart() + ".." + a.getWindowEnd());
        return a;
    }

    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    @Transactional
    public Authorization reject(String authorizationId, String note, String actor) {
        Authorization a = load(authorizationId);
        if (a.getStatus() != AuthStatus.PENDING_APPROVAL) {
            throw new IllegalStateException("Only a pending authorization can be rejected (current: " + a.getStatus() + ").");
        }
        a.setStatus(AuthStatus.REJECTED);
        a.setApprovedBy(actor);
        a.setApprovedAt(Instant.now());
        a.setDecisionNote(note);
        authorizations.save(a);
        audit.record(actor, "authorization.rejected", "Authorization", a.getId(), note);
        return a;
    }

    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    @Transactional
    public Authorization revoke(String authorizationId, String note, String actor) {
        Authorization a = load(authorizationId);
        if (a.getStatus() != AuthStatus.SIGNED) {
            throw new IllegalStateException("Only a signed authorization can be revoked (current: " + a.getStatus() + ").");
        }
        a.setStatus(AuthStatus.REVOKED);
        a.setDecisionNote(note);
        authorizations.save(a);
        audit.record(actor, "authorization.revoked", "Authorization", a.getId(), note);
        return a;
    }

    @Transactional(readOnly = true)
    public List<Authorization> list(String engagementId) {
        access.requireEngagement(engagementId);
        return authorizations.findByEngagementIdOrderByCreatedAtDesc(engagementId);
    }

    private Authorization load(String id) {
        Authorization a = authorizations.findById(id).orElseThrow(() -> new NotFoundException("Authorization not found"));
        access.requireEngagement(a.getEngagementId());
        return a;
    }
}
