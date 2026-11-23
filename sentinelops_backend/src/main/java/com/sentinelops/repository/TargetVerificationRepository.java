package com.sentinelops.repository;

import com.sentinelops.entity.ChallengeStatus;
import com.sentinelops.entity.TargetVerification;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TargetVerificationRepository extends JpaRepository<TargetVerification, String> {
    List<TargetVerification> findByTargetIdOrderByCreatedAtDesc(String targetId);
    List<TargetVerification> findByTargetIdAndStatus(String targetId, ChallengeStatus status);
    Optional<TargetVerification> findFirstByTargetIdAndStatusOrderByCreatedAtDesc(String targetId, ChallengeStatus status);
}
