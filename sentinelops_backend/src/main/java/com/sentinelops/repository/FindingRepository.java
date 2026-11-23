package com.sentinelops.repository;

import com.sentinelops.entity.Finding;
import com.sentinelops.entity.FindingStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface FindingRepository extends JpaRepository<Finding, String> {
    List<Finding> findByEngagementId(String engagementId);

    Optional<Finding> findFirstByEngagementIdAndFingerprint(String engagementId, String fingerprint);

    List<Finding> findByTargetIdAndToolAndStatus(String targetId, String tool, FindingStatus status);
}
