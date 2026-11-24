package com.sentinelops.controller;

import com.sentinelops.dto.BusinessLogicProbeDtos.BusinessLogicProbeRequest;
import com.sentinelops.service.BusinessLogicProbeService;
import com.sentinelops.service.LogicTestService;
import com.sentinelops.util.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/** Phase 4 of the logic-testing engine: checkout / business-logic probes (see PENTEST_COVERAGE_PLAN.md). */
@RestController
@RequestMapping("/api/engagements/{id}/targets/{tid}/business-probes")
public class BusinessLogicProbeController {

    private final BusinessLogicProbeService probes;
    private final LogicTestService logic;

    public BusinessLogicProbeController(BusinessLogicProbeService probes, LogicTestService logic) {
        this.probes = probes;
        this.logic = logic;
    }

    @GetMapping
    public List<BusinessLogicProbeService.View> list(@PathVariable String id, @PathVariable String tid) {
        return probes.list(id, tid);
    }

    @PostMapping
    public ResponseEntity<BusinessLogicProbeService.View> create(@PathVariable String id, @PathVariable String tid,
                                                                 @Valid @RequestBody BusinessLogicProbeRequest r) {
        var v = probes.create(id, tid, r.label(), r.requestUrl(), r.httpMethod(), r.bodyTemplate(),
                r.tamperedField(), r.tamperedValue(), r.concurrency(), r.identityId(), CurrentUser.email());
        return ResponseEntity.status(201).body(v);
    }

    @DeleteMapping("/{probeId}")
    public ResponseEntity<Void> delete(@PathVariable String id, @PathVariable String tid, @PathVariable String probeId) {
        probes.delete(id, tid, probeId, CurrentUser.email());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{probeId}/run")
    public LogicTestService.RunResult run(@PathVariable String id, @PathVariable String tid, @PathVariable String probeId) {
        return logic.runBusinessLogicCheck(id, tid, probeId, CurrentUser.email());
    }
}
