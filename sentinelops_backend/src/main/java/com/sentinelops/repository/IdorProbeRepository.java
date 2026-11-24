package com.sentinelops.repository;

import com.sentinelops.entity.IdorProbe;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IdorProbeRepository extends JpaRepository<IdorProbe, String> {
    List<IdorProbe> findByTargetIdOrderByCreatedAtAsc(String targetId);
}
