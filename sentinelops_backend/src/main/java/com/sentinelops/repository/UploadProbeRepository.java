package com.sentinelops.repository;

import com.sentinelops.entity.UploadProbe;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface UploadProbeRepository extends JpaRepository<UploadProbe, String> {
    List<UploadProbe> findByTargetIdOrderByCreatedAtAsc(String targetId);
}
