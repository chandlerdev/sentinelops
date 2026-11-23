package com.sentinelops.repository;

import com.sentinelops.entity.AuditLog;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, String> {
    List<AuditLog> findByOrderByCreatedAtDesc(Pageable page);
    List<AuditLog> findByEntityAndEntityIdOrderByCreatedAtDesc(String entity, String entityId, Pageable page);
}
