package com.sentinelops.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelops.entity.DependencyEcosystem;
import com.sentinelops.entity.DependencyManifest;
import com.sentinelops.entity.Target;
import com.sentinelops.exception.NotFoundException;
import com.sentinelops.repository.DependencyManifestRepository;
import com.sentinelops.repository.TargetRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Phase 6 of the logic-testing engine (L: dependency / SCA scanning; see PENTEST_COVERAGE_PLAN.md). Stores
 * an uploaded package-lock.json. This scans a FILE, never the target's live infrastructure, so it needs no
 * authorization gate - only the normal engagement access check every other target-scoped action already has.
 */
@Service
public class DependencyManifestService {

    private static final Pattern LABEL = Pattern.compile("^[A-Za-z0-9 ._-]{1,64}$");
    private static final int MAX_CONTENT_CHARS = 4_000_000;
    private static final ObjectMapper JSON = new ObjectMapper();

    public record View(String id, String targetId, String label, DependencyEcosystem ecosystem,
                       int contentLength, String createdBy, Instant createdAt) {
        static View from(DependencyManifest m) {
            return new View(m.getId(), m.getTargetId(), m.getLabel(), m.getEcosystem(),
                    m.getManifestContent().length(), m.getCreatedBy(), m.getCreatedAt());
        }
    }

    private final DependencyManifestRepository manifests;
    private final TargetRepository targets;
    private final AccessService access;
    private final AuditService audit;

    public DependencyManifestService(DependencyManifestRepository manifests, TargetRepository targets,
                                     AccessService access, AuditService audit) {
        this.manifests = manifests;
        this.targets = targets;
        this.access = access;
        this.audit = audit;
    }

    Target target(String engagementId, String targetId) {
        access.requireEngagement(engagementId);
        Target t = targets.findById(targetId).orElseThrow(() -> new NotFoundException("Target not found"));
        if (!t.getEngagementId().equals(engagementId)) throw new NotFoundException("Target not found");
        return t;
    }

    DependencyManifest manifest(String targetId, String manifestId) {
        DependencyManifest m = manifests.findById(manifestId).orElseThrow(() -> new NotFoundException("Dependency manifest not found"));
        if (!m.getTargetId().equals(targetId)) throw new NotFoundException("Dependency manifest not found");
        return m;
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public View create(String engagementId, String targetId, String label, DependencyEcosystem ecosystem,
                       String manifestContent, String actor) {
        target(engagementId, targetId);

        if (label == null || !LABEL.matcher(label).matches()) {
            throw new IllegalArgumentException("Label must be 1-64 letters, digits, spaces, '.', '_' or '-'.");
        }
        DependencyEcosystem eco = ecosystem == null ? DependencyEcosystem.NPM : ecosystem;
        if (manifestContent == null || manifestContent.isBlank()) {
            throw new IllegalArgumentException("Manifest content is required.");
        }
        if (manifestContent.length() > MAX_CONTENT_CHARS) {
            throw new IllegalArgumentException("Manifest is too large (max " + MAX_CONTENT_CHARS + " characters).");
        }
        JsonNode parsed;
        try {
            parsed = JSON.readTree(manifestContent);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Manifest content must be valid JSON.");
        }
        if (!parsed.isObject() || !(parsed.has("lockfileVersion") || parsed.has("packages") || parsed.has("dependencies"))) {
            throw new IllegalArgumentException("This does not look like a package-lock.json (expected \"lockfileVersion\", "
                    + "\"packages\" or \"dependencies\").");
        }

        DependencyManifest m = new DependencyManifest(UUID.randomUUID().toString(), targetId, label.trim(), eco,
                manifestContent, actor);
        manifests.save(m);
        audit.record(actor, "dependency_manifest.created", "Target", targetId, "label=" + m.getLabel());
        return View.from(m);
    }

    @Transactional(readOnly = true)
    public List<View> list(String engagementId, String targetId) {
        target(engagementId, targetId);
        return manifests.findByTargetIdOrderByCreatedAtAsc(targetId).stream().map(View::from).toList();
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public void delete(String engagementId, String targetId, String manifestId, String actor) {
        target(engagementId, targetId);
        DependencyManifest m = manifest(targetId, manifestId);
        manifests.delete(m);
        audit.record(actor, "dependency_manifest.deleted", "Target", targetId, "label=" + m.getLabel());
    }
}
