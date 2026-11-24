package com.sentinelops.controller;

import com.sentinelops.dto.IdorProbeDtos.IdorProbeRequest;
import com.sentinelops.service.IdorProbeService;
import com.sentinelops.service.LogicTestService;
import com.sentinelops.util.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Phase 2 of the logic-testing engine: authorization/IDOR probes pairing two test identities (see
 * PENTEST_COVERAGE_PLAN.md).
 */
@RestController
@RequestMapping("/api/engagements/{id}/targets/{tid}/idor-probes")
public class IdorProbeController {

    private final IdorProbeService probes;
    private final LogicTestService logic;

    public IdorProbeController(IdorProbeService probes, LogicTestService logic) {
        this.probes = probes;
        this.logic = logic;
    }

    @GetMapping
    public List<IdorProbeService.View> list(@PathVariable String id, @PathVariable String tid) {
        return probes.list(id, tid);
    }

    @PostMapping
    public ResponseEntity<IdorProbeService.View> create(@PathVariable String id, @PathVariable String tid,
                                                        @Valid @RequestBody IdorProbeRequest r) {
        var v = probes.create(id, tid, r.label(), r.urlTemplate(), r.identityAId(), r.resourceIdA(),
                r.identityBId(), r.resourceIdB(), CurrentUser.email());
        return ResponseEntity.status(201).body(v);
    }

    @DeleteMapping("/{probeId}")
    public ResponseEntity<Void> delete(@PathVariable String id, @PathVariable String tid, @PathVariable String probeId) {
        probes.delete(id, tid, probeId, CurrentUser.email());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{probeId}/run")
    public LogicTestService.RunResult run(@PathVariable String id, @PathVariable String tid, @PathVariable String probeId) {
        return logic.runIdorCheck(id, tid, probeId, CurrentUser.email());
    }
}
