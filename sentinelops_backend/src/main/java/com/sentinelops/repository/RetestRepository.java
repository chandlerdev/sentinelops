package com.sentinelops.repository;

import com.sentinelops.entity.Retest;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RetestRepository extends JpaRepository<Retest, String> {
    List<Retest> findByFindingIdOrderByTestedAtDesc(String findingId);
}
