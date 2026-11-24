package com.sentinelops.service;

import com.sentinelops.entity.IdorProbe;
import com.sentinelops.entity.Target;
import com.sentinelops.entity.TargetKind;
import com.sentinelops.entity.TestIdentity;
import com.sentinelops.exception.NotFoundException;
import com.sentinelops.repository.IdorProbeRepository;
import com.sentinelops.util.TargetParser;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Phase 2 of the logic-testing engine (D: authorization / IDOR; see PENTEST_COVERAGE_PLAN.md). Stores the
 * pairing of two test identities with their own object id on one URL template, so {@link LogicTestService}
 * can try each one's id with the other's session.
 */
@Service
public class IdorProbeService {

    private static final Pattern LABEL = Pattern.compile("^[A-Za-z0-9 ._-]{1,64}$");
    private static final Pattern RESOURCE_ID = Pattern.compile("^[A-Za-z0-9_-]{1,128}$");

    public record View(String id, String targetId, String label, String urlTemplate,
                       String identityAId, String resourceIdA, String identityBId, String resourceIdB,
                       String createdBy, Instant createdAt) {
        static View from(IdorProbe p) {
            return new View(p.getId(), p.getTargetId(), p.getLabel(), p.getUrlTemplate(), p.getIdentityAId(),
                    p.getResourceIdA(), p.getIdentityBId(), p.getResourceIdB(), p.getCreatedBy(), p.getCreatedAt());
        }
    }

    private final IdorProbeRepository probes;
    private final TestIdentityService identities;
    private final AuditService audit;

    public IdorProbeService(IdorProbeRepository probes, TestIdentityService identities, AuditService audit) {
        this.probes = probes;
        this.identities = identities;
        this.audit = audit;
    }

    IdorProbe probe(String targetId, String probeId) {
        IdorProbe p = probes.findById(probeId).orElseThrow(() -> new NotFoundException("IDOR probe not found"));
        if (!p.getTargetId().equals(targetId)) throw new NotFoundException("IDOR probe not found");
        return p;
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public View create(String engagementId, String targetId, String label, String urlTemplate, String identityAId,
                       String resourceIdA, String identityBId, String resourceIdB, String actor) {
        Target t = identities.target(engagementId, targetId);
        if (t.getKind() == TargetKind.CIDR) throw new IllegalArgumentException("A range cannot hold an IDOR probe.");

        if (label == null || !LABEL.matcher(label).matches()) {
            throw new IllegalArgumentException("Label must be 1-64 letters, digits, spaces, '.', '_' or '-'.");
        }
        if (urlTemplate == null || urlTemplate.isBlank()) throw new IllegalArgumentException("URL template is required.");
        String template = urlTemplate.trim();
        if (countOccurrences(template, "{id}") != 1) {
            throw new IllegalArgumentException("The URL template must contain the placeholder \"{id}\" exactly once.");
        }
        String host;
        try {
            host = TargetParser.hostOfUrl(template.replace("{id}", "placeholder"));
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("URL template: " + ex.getMessage());
        }
        if (!host.equals(t.getValue())) {
            throw new IllegalArgumentException("The URL template must be on the target's own host.");
        }
        if (identityAId == null || identityBId == null || identityAId.equals(identityBId)) {
            throw new IllegalArgumentException("Pick two different test identities.");
        }
        TestIdentity a = identities.identity(targetId, identityAId); // throws NotFoundException if missing/foreign
        TestIdentity b = identities.identity(targetId, identityBId);
        if (resourceIdA == null || !RESOURCE_ID.matcher(resourceIdA).matches()
                || resourceIdB == null || !RESOURCE_ID.matcher(resourceIdB).matches()) {
            throw new IllegalArgumentException("Resource ids must be 1-128 letters, digits, '_' or '-'.");
        }
        if (resourceIdA.equals(resourceIdB)) {
            throw new IllegalArgumentException("The two resource ids must be different (otherwise there is nothing to cross-check).");
        }

        IdorProbe p = new IdorProbe(UUID.randomUUID().toString(), targetId, label.trim(), template,
                a.getId(), resourceIdA, b.getId(), resourceIdB, actor);
        probes.save(p);
        audit.record(actor, "idor_probe.created", "Target", targetId, "label=" + p.getLabel() + " template=" + template);
        return View.from(p);
    }

    @Transactional(readOnly = true)
    public List<View> list(String engagementId, String targetId) {
        identities.target(engagementId, targetId);
        return probes.findByTargetIdOrderByCreatedAtAsc(targetId).stream().map(View::from).toList();
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public void delete(String engagementId, String targetId, String probeId, String actor) {
        identities.target(engagementId, targetId);
        IdorProbe p = probe(targetId, probeId);
        probes.delete(p);
        audit.record(actor, "idor_probe.deleted", "Target", targetId, "label=" + p.getLabel());
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0, idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) != -1) { count++; idx += needle.length(); }
        return count;
    }
}
