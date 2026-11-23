package com.sentinelops.repository;

import com.sentinelops.entity.AuthStatus;
import com.sentinelops.entity.Authorization;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuthorizationRepository extends JpaRepository<Authorization, String> {
    List<Authorization> findByEngagementIdOrderByCreatedAtDesc(String engagementId);
    List<Authorization> findByEngagementIdAndStatus(String engagementId, AuthStatus status);
}
