package com.sentinelops.repository;

import com.sentinelops.entity.DependencyManifest;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface DependencyManifestRepository extends JpaRepository<DependencyManifest, String> {
    List<DependencyManifest> findByTargetIdOrderByCreatedAtAsc(String targetId);
}
