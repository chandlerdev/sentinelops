package com.sentinelops.repository;

import com.sentinelops.entity.BusinessLogicProbe;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface BusinessLogicProbeRepository extends JpaRepository<BusinessLogicProbe, String> {
    List<BusinessLogicProbe> findByTargetIdOrderByCreatedAtAsc(String targetId);
}
