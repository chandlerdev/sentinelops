package com.sentinelops.controller;

import com.sentinelops.dto.UploadProbeDtos.UploadProbeRequest;
import com.sentinelops.service.LogicTestService;
import com.sentinelops.service.UploadProbeService;
import com.sentinelops.util.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/** Phase 3 of the logic-testing engine: file-upload / extension-bypass probes (see PENTEST_COVERAGE_PLAN.md). */
@RestController
@RequestMapping("/api/engagements/{id}/targets/{tid}/upload-probes")
public class UploadProbeController {

    private final UploadProbeService probes;
    private final LogicTestService logic;

    public UploadProbeController(UploadProbeService probes, LogicTestService logic) {
        this.probes = probes;
        this.logic = logic;
    }

    @GetMapping
    public List<UploadProbeService.View> list(@PathVariable String id, @PathVariable String tid) {
        return probes.list(id, tid);
    }

    @PostMapping
    public ResponseEntity<UploadProbeService.View> create(@PathVariable String id, @PathVariable String tid,
                                                          @Valid @RequestBody UploadProbeRequest r) {
        var v = probes.create(id, tid, r.label(), r.uploadUrl(), r.fieldName(), r.retrievalUrlTemplate(),
                r.identityId(), CurrentUser.email());
        return ResponseEntity.status(201).body(v);
    }

    @DeleteMapping("/{probeId}")
    public ResponseEntity<Void> delete(@PathVariable String id, @PathVariable String tid, @PathVariable String probeId) {
        probes.delete(id, tid, probeId, CurrentUser.email());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{probeId}/run")
    public LogicTestService.RunResult run(@PathVariable String id, @PathVariable String tid, @PathVariable String probeId) {
        return logic.runUploadCheck(id, tid, probeId, CurrentUser.email());
    }
}
