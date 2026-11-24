package com.sentinelops.service;

import com.sentinelops.entity.Target;
import com.sentinelops.entity.TargetKind;
import com.sentinelops.entity.UploadProbe;
import com.sentinelops.exception.NotFoundException;
import com.sentinelops.repository.UploadProbeRepository;
import com.sentinelops.util.TargetParser;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Phase 3 of the logic-testing engine (H: file upload / extension bypass, FILE-06; see
 * PENTEST_COVERAGE_PLAN.md). Stores where to upload a marker file and where to try to fetch it back.
 */
@Service
public class UploadProbeService {

    private static final Pattern LABEL = Pattern.compile("^[A-Za-z0-9 ._-]{1,64}$");
    private static final Pattern FIELD_NAME = Pattern.compile("^[A-Za-z][A-Za-z0-9_]{0,63}$");

    public record View(String id, String targetId, String label, String uploadUrl, String fieldName,
                       String retrievalUrlTemplate, String identityId, String createdBy, Instant createdAt) {
        static View from(UploadProbe p) {
            return new View(p.getId(), p.getTargetId(), p.getLabel(), p.getUploadUrl(), p.getFieldName(),
                    p.getRetrievalUrlTemplate(), p.getIdentityId(), p.getCreatedBy(), p.getCreatedAt());
        }
    }

    private final UploadProbeRepository probes;
    private final TestIdentityService identities;
    private final AuditService audit;

    public UploadProbeService(UploadProbeRepository probes, TestIdentityService identities, AuditService audit) {
        this.probes = probes;
        this.identities = identities;
        this.audit = audit;
    }

    UploadProbe probe(String targetId, String probeId) {
        UploadProbe p = probes.findById(probeId).orElseThrow(() -> new NotFoundException("Upload probe not found"));
        if (!p.getTargetId().equals(targetId)) throw new NotFoundException("Upload probe not found");
        return p;
    }

    private String sameHostUrl(String url, String fieldName, Target t, String placeholder) {
        if (url == null || url.isBlank()) throw new IllegalArgumentException(fieldName + " is required.");
        String host;
        try {
            host = TargetParser.hostOfUrl(placeholder == null ? url.trim() : url.trim().replace(placeholder, "x"));
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException(fieldName + ": " + ex.getMessage());
        }
        if (!host.equals(t.getValue())) throw new IllegalArgumentException(fieldName + " must be on the target's own host.");
        return url.trim();
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public View create(String engagementId, String targetId, String label, String uploadUrl, String fieldName,
                       String retrievalUrlTemplate, String identityId, String actor) {
        Target t = identities.target(engagementId, targetId);
        if (t.getKind() == TargetKind.CIDR) throw new IllegalArgumentException("A range cannot hold an upload probe.");

        if (label == null || !LABEL.matcher(label).matches()) {
            throw new IllegalArgumentException("Label must be 1-64 letters, digits, spaces, '.', '_' or '-'.");
        }
        String upload = sameHostUrl(uploadUrl, "Upload URL", t, null);
        if (retrievalUrlTemplate == null || countOccurrences(retrievalUrlTemplate, "{filename}") != 1) {
            throw new IllegalArgumentException("The retrieval URL template must contain the placeholder \"{filename}\" exactly once.");
        }
        String retrieval = sameHostUrl(retrievalUrlTemplate, "Retrieval URL template", t, "{filename}");
        String field = fieldName == null || fieldName.isBlank() ? "file" : fieldName.trim();
        if (!FIELD_NAME.matcher(field).matches()) {
            throw new IllegalArgumentException("Field name must start with a letter and contain only letters, digits or '_'.");
        }
        String identity = null;
        if (identityId != null && !identityId.isBlank()) {
            identity = identities.identity(targetId, identityId).getId(); // throws NotFoundException if missing/foreign
        }

        UploadProbe p = new UploadProbe(UUID.randomUUID().toString(), targetId, label.trim(), upload, field,
                retrieval, identity, actor);
        probes.save(p);
        audit.record(actor, "upload_probe.created", "Target", targetId, "label=" + p.getLabel() + " uploadUrl=" + upload);
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
        UploadProbe p = probe(targetId, probeId);
        probes.delete(p);
        audit.record(actor, "upload_probe.deleted", "Target", targetId, "label=" + p.getLabel());
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0, idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) != -1) { count++; idx += needle.length(); }
        return count;
    }
}
