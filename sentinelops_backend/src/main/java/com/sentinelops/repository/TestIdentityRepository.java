package com.sentinelops.repository;

import com.sentinelops.entity.TestIdentity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TestIdentityRepository extends JpaRepository<TestIdentity, String> {
    List<TestIdentity> findByTargetIdOrderByCreatedAtAsc(String targetId);
}
