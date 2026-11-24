package com.sentinelops.controller;

import com.sentinelops.dto.DependencyManifestDtos.DependencyManifestRequest;
import com.sentinelops.service.DependencyManifestService;
import com.sentinelops.service.LogicTestService;
import com.sentinelops.util.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/** Phase 6 of the logic-testing engine: dependency / SCA scanning (see PENTEST_COVERAGE_PLAN.md). */
@RestController
@RequestMapping("/api/engagements/{id}/targets/{tid}/dependency-manifests")
public class DependencyManifestController {

    private final DependencyManifestService manifests;
    private final LogicTestService logic;

    public DependencyManifestController(DependencyManifestService manifests, LogicTestService logic) {
        this.manifests = manifests;
        this.logic = logic;
    }

    @GetMapping
    public List<DependencyManifestService.View> list(@PathVariable String id, @PathVariable String tid) {
        return manifests.list(id, tid);
    }

    @PostMapping
    public ResponseEntity<DependencyManifestService.View> create(@PathVariable String id, @PathVariable String tid,
                                                                 @Valid @RequestBody DependencyManifestRequest r) {
        var v = manifests.create(id, tid, r.label(), r.ecosystem(), r.manifestContent(), CurrentUser.email());
        return ResponseEntity.status(201).body(v);
    }

    @DeleteMapping("/{manifestId}")
    public ResponseEntity<Void> delete(@PathVariable String id, @PathVariable String tid, @PathVariable String manifestId) {
        manifests.delete(id, tid, manifestId, CurrentUser.email());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{manifestId}/run")
    public LogicTestService.RunResult run(@PathVariable String id, @PathVariable String tid, @PathVariable String manifestId) {
        return logic.runDependencyCheck(id, tid, manifestId, CurrentUser.email());
    }
}
