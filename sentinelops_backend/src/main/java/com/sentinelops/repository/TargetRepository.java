package com.sentinelops.repository;

import com.sentinelops.entity.Target;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TargetRepository extends JpaRepository<Target, String> {
    List<Target> findByEngagementIdOrderByCreatedAtAsc(String engagementId);
    Optional<Target> findByEngagementIdAndValue(String engagementId, String value);
}
