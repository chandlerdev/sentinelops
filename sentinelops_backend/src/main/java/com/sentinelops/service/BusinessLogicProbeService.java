package com.sentinelops.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelops.entity.BusinessLogicProbe;
import com.sentinelops.entity.Target;
import com.sentinelops.entity.TargetKind;
import com.sentinelops.repository.BusinessLogicProbeRepository;
import com.sentinelops.util.TargetParser;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Phase 4 of the logic-testing engine (E/J: checkout / business logic; see PENTEST_COVERAGE_PLAN.md).
 * Stores one request shape (URL, method, JSON body) and an optional field to tamper, so
 * {@link LogicTestService} can replay it as-is, tampered, and concurrently.
 */
@Service
public class BusinessLogicProbeService {

    private static final Pattern LABEL = Pattern.compile("^[A-Za-z0-9 ._-]{1,64}$");
    private static final Pattern FIELD_NAME = Pattern.compile("^[A-Za-z0-9_-]{1,128}$");
    private static final Set<String> METHODS = Set.of("POST", "PUT");
    private static final ObjectMapper JSON = new ObjectMapper();

    public record View(String id, String targetId, String label, String requestUrl, String httpMethod,
                       String bodyTemplate, String tamperedField, String tamperedValue, int concurrency,
                       String identityId, String createdBy, Instant createdAt) {
        static View from(BusinessLogicProbe p) {
            return new View(p.getId(), p.getTargetId(), p.getLabel(), p.getRequestUrl(), p.getHttpMethod(),
                    p.getBodyTemplate(), p.getTamperedField(), p.getTamperedValue(), p.getConcurrency(),
                    p.getIdentityId(), p.getCreatedBy(), p.getCreatedAt());
        }
    }

    private final BusinessLogicProbeRepository probes;
    private final TestIdentityService identities;
    private final AuditService audit;

    public BusinessLogicProbeService(BusinessLogicProbeRepository probes, TestIdentityService identities, AuditService audit) {
        this.probes = probes;
        this.identities = identities;
        this.audit = audit;
    }

    BusinessLogicProbe probe(String targetId, String probeId) {
        BusinessLogicProbe p = probes.findById(probeId)
                .orElseThrow(() -> new com.sentinelops.exception.NotFoundException("Business logic probe not found"));
        if (!p.getTargetId().equals(targetId)) throw new com.sentinelops.exception.NotFoundException("Business logic probe not found");
        return p;
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public View create(String engagementId, String targetId, String label, String requestUrl, String httpMethod,
                       String bodyTemplate, String tamperedField, String tamperedValue, Integer concurrency,
                       String identityId, String actor) {
        Target t = identities.target(engagementId, targetId);
        if (t.getKind() == TargetKind.CIDR) throw new IllegalArgumentException("A range cannot hold a business logic probe.");

        if (label == null || !LABEL.matcher(label).matches()) {
            throw new IllegalArgumentException("Label must be 1-64 letters, digits, spaces, '.', '_' or '-'.");
        }
        if (requestUrl == null || requestUrl.isBlank()) throw new IllegalArgumentException("Request URL is required.");
        String host;
        try {
            host = TargetParser.hostOfUrl(requestUrl.trim());
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Request URL: " + ex.getMessage());
        }
        if (!host.equals(t.getValue())) throw new IllegalArgumentException("Request URL must be on the target's own host.");

        String method = httpMethod == null || httpMethod.isBlank() ? "POST" : httpMethod.trim().toUpperCase();
        if (!METHODS.contains(method)) throw new IllegalArgumentException("HTTP method must be POST or PUT.");

        if (bodyTemplate == null || bodyTemplate.isBlank() || bodyTemplate.length() > 4000) {
            throw new IllegalArgumentException("Body template is required (max 4000 characters).");
        }
        JsonNode parsedBody;
        try {
            parsedBody = JSON.readTree(bodyTemplate);
            if (!parsedBody.isObject()) throw new IllegalArgumentException("not an object");
        } catch (Exception ex) {
            throw new IllegalArgumentException("Body template must be a valid JSON object.");
        }

        String tField = null, tValue = null;
        if (tamperedField != null && !tamperedField.isBlank()) {
            tField = tamperedField.trim();
            if (!FIELD_NAME.matcher(tField).matches()) {
                throw new IllegalArgumentException("Tampered field may only contain letters, digits, '_' or '-'.");
            }
            if (!parsedBody.has(tField)) {
                throw new IllegalArgumentException("Tampered field must be a top-level key already present in the body template.");
            }
            if (tamperedValue == null || tamperedValue.isBlank() || tamperedValue.length() > 512) {
                throw new IllegalArgumentException("Tampered value is required when a tampered field is set (max 512 characters).");
            }
            try {
                JSON.readTree(tamperedValue);
            } catch (Exception ex) {
                throw new IllegalArgumentException("Tampered value must be valid JSON (e.g. 0.01, -5, true, or \"CODE\" for a string).");
            }
            tValue = tamperedValue.trim();
        }

        int conc = concurrency == null ? 5 : concurrency;
        if (conc < 2 || conc > 10) throw new IllegalArgumentException("Concurrency must be between 2 and 10.");

        String identity = null;
        if (identityId != null && !identityId.isBlank()) {
            identity = identities.identity(targetId, identityId).getId(); // throws NotFoundException if missing/foreign
        }

        BusinessLogicProbe p = new BusinessLogicProbe(UUID.randomUUID().toString(), targetId, label.trim(),
                requestUrl.trim(), method, bodyTemplate.trim(), tField, tValue, conc, identity, actor);
        probes.save(p);
        audit.record(actor, "business_logic_probe.created", "Target", targetId,
                "label=" + p.getLabel() + " requestUrl=" + p.getRequestUrl());
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
        BusinessLogicProbe p = probe(targetId, probeId);
        probes.delete(p);
        audit.record(actor, "business_logic_probe.deleted", "Target", targetId, "label=" + p.getLabel());
    }
}
