package com.sentinelops.repository;

import com.sentinelops.entity.ScanRun;
import com.sentinelops.entity.ScanStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface ScanRunRepository extends JpaRepository<ScanRun, String> {
    List<ScanRun> findByEngagementId(String engagementId);

    List<ScanRun> findByEngagementIdOrderByCreatedAtDesc(String engagementId);

    Optional<ScanRun> findFirstByStatusOrderByCreatedAtAsc(ScanStatus status);

    List<ScanRun> findByStatus(ScanStatus status);

    boolean existsByTargetIdAndCategoryAndStatusIn(String targetId, com.sentinelops.entity.ScanCategory category,
                                                   java.util.Collection<ScanStatus> statuses);

    /** Atomically takes a queued run. Returns 1 if this caller won it, 0 if it was already taken or stopped. */
    @Transactional
    @Modifying
    @Query("update ScanRun r set r.status = com.sentinelops.entity.ScanStatus.RUNNING, r.startedAt = :now "
            + "where r.id = :id and r.status = com.sentinelops.entity.ScanStatus.QUEUED")
    int claim(@Param("id") String id, @Param("now") Instant now);
}
