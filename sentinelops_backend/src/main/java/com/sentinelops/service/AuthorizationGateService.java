package com.sentinelops.service;

import com.sentinelops.entity.*;
import com.sentinelops.repository.AuthorizationRepository;
import com.sentinelops.repository.TargetRepository;
import com.sentinelops.util.Cidr;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * The authorization gate: the single source of truth for whether a target may be tested.
 * Every scan path MUST consult this before invoking any scanner, and again when the scan starts.
 *
 * A gate passes only when ALL of these hold:
 *  1. the target belongs to the engagement;
 *  2. its ownership is verified and the verification has not expired (lab assets: lab allowlist);
 *  3. a SIGNED authorization of the engagement covers the target;
 *  4. that authorization is inside its window, not expired, and permits the requested method;
 *  5. the target is not on the authorization's exclusion list;
 *  6. a FRESH DNS resolution of the target yields only allowed addresses (no private/loopback/
 *     metadata/server addresses, except the explicit lab exception).
 */
@Service
public class AuthorizationGateService {

    private final AuthorizationRepository authorizations;
    private final TargetRepository targets;
    private final ScopeValidator scope;

    public AuthorizationGateService(AuthorizationRepository authorizations, TargetRepository targets,
                                    ScopeValidator scope) {
        this.authorizations = authorizations;
        this.targets = targets;
        this.scope = scope;
    }

    public record GateResult(boolean allowed, String reason, Authorization authorization, Target target,
                             List<String> addresses) {
        static GateResult deny(String reason, Target target, List<String> addresses) {
            return new GateResult(false, reason, null, target, addresses);
        }
        static GateResult allow(Authorization a, Target t, List<String> addresses) {
            return new GateResult(true, null, a, t, addresses);
        }
    }

    public GateResult evaluate(String engagementId, String targetId, ScanCategory category, Instant now) {
        Optional<Target> maybe = targets.findById(targetId);
        if (maybe.isEmpty() || !maybe.get().getEngagementId().equals(engagementId)) {
            return GateResult.deny("Target is not registered in this engagement.", null, List.of());
        }
        Target target = maybe.get();

        if (!target.isOwnershipEstablishedAt(now)) {
            return GateResult.deny("Target ownership is not verified (or the verification has expired).",
                    target, List.of());
        }

        List<Authorization> covering = authorizations
                .findByEngagementIdAndStatus(engagementId, AuthStatus.SIGNED).stream()
                .filter(a -> a.getTargetIds().contains(targetId))
                .toList();
        if (covering.isEmpty()) {
            return GateResult.deny("No signed authorization covers this target.", target, List.of());
        }

        String lastReason = "No valid authorization.";
        for (Authorization a : covering) {
            String problem = checkAuthorization(a, category, now);
            if (problem != null) {
                lastReason = problem;
                continue;
            }
            // Fresh resolution + address policy, every time.
            ScopeValidator.Check sc = scope.checkTarget(target);
            if (!sc.allowed()) {
                return GateResult.deny(sc.reason(), target, sc.addresses());
            }
            if (isExcluded(target, a.getExcludedAssetList(), sc.addresses())) {
                return GateResult.deny("Target is on the authorization's exclusion list.", target, sc.addresses());
            }
            return GateResult.allow(a, target, sc.addresses());
        }
        return GateResult.deny(lastReason, target, List.of());
    }

    private String checkAuthorization(Authorization a, ScanCategory category, Instant now) {
        if (a.getExpiresAt() != null && a.getExpiresAt().isBefore(now)) return "Authorization has expired.";
        if (a.getWindowStart() == null || a.getWindowEnd() == null) return "Authorization has no testing window.";
        if (now.isBefore(a.getWindowStart())) return "Current time is before the approved testing window.";
        if (now.isAfter(a.getWindowEnd())) return "Current time is after the approved testing window.";
        if (!a.getPermittedMethodSet().contains(category)) {
            return "Authorization does not permit " + category + " testing.";
        }
        return null;
    }

    /** True when the target (by name, by IP/CIDR overlap, or by any resolved address) is excluded. */
    boolean isExcluded(Target target, List<String> excluded, List<String> resolvedAddresses) {
        for (String raw : excluded) {
            String entry = raw.trim().toLowerCase(Locale.ROOT);
            if (entry.isEmpty()) continue;
            if (entry.equals(target.getValue())) return true;
            if (target.getKind() == TargetKind.DOMAIN && target.getValue().endsWith("." + entry)) return true;

            if (entry.contains("/") || Cidr.isIpLiteral(entry)) {
                Cidr ex;
                try {
                    ex = Cidr.parse(entry);
                } catch (IllegalArgumentException e) {
                    continue;
                }
                if (target.getKind() == TargetKind.CIDR) {
                    if (ex.overlaps(Cidr.parse(target.getValue()))) return true;
                } else if (target.getKind() == TargetKind.IP) {
                    if (ex.contains(Cidr.parseLiteral(target.getValue()))) return true;
                }
                for (String addr : resolvedAddresses) {
                    if (Cidr.isIpLiteral(addr) && ex.contains(Cidr.parseLiteral(addr))) return true;
                }
            }
        }
        return false;
    }
}
