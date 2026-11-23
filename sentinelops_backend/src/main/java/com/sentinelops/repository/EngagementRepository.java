package com.sentinelops.repository;

import com.sentinelops.entity.Engagement;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface EngagementRepository extends JpaRepository<Engagement, String> {
    List<Engagement> findByClientId(String clientId);
}
