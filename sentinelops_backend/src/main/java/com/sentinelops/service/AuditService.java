package com.sentinelops.service;

import com.sentinelops.entity.AuditLog;
import com.sentinelops.repository.AuditLogRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/** Append-only audit trail: records are only ever inserted, never updated or deleted by the application. */
@Service
public class AuditService {

    private final AuditLogRepository repo;

    public AuditService(AuditLogRepository repo) {
        this.repo = repo;
    }

    /**
     * Runs in its OWN transaction so the entry survives even when the caller's transaction rolls back
     * (e.g. a refused scan or a rejected target must still be recorded).
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(String actor, String action, String entity, String entityId, String detail) {
        repo.save(new AuditLog(UUID.randomUUID().toString(), actor, action, entity, entityId, detail));
    }

    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    @Transactional(readOnly = true)
    public List<AuditLog> recent(String entity, String entityId, int limit) {
        var page = PageRequest.of(0, Math.max(1, Math.min(limit, 500)));
        if (entity != null && !entity.isBlank() && entityId != null && !entityId.isBlank()) {
            return repo.findByEntityAndEntityIdOrderByCreatedAtDesc(entity, entityId, page);
        }
        return repo.findByOrderByCreatedAtDesc(page);
    }
}
