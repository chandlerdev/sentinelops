package com.sentinelops.repository;

import com.sentinelops.entity.ScanSchedule;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;

public interface ScanScheduleRepository extends JpaRepository<ScanSchedule, String> {
    List<ScanSchedule> findByEngagementIdOrderByCreatedAtAsc(String engagementId);

    List<ScanSchedule> findByEnabledTrueAndNextRunAtLessThanEqual(Instant now);
}
