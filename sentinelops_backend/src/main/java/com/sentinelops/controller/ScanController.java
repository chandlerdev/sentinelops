package com.sentinelops.controller;

import com.sentinelops.dto.ScanDtos.ScanRunView;
import com.sentinelops.dto.ScanRequest;
import com.sentinelops.service.ScanService;
import com.sentinelops.util.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class ScanController {

    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    /**
     * Request an authorized scan. The gate is enforced inside ScanService (denied = 403); a permitted request is
     * QUEUED, one run per tool, and executed by the background worker.
     */
    @PostMapping("/engagements/{id}/scan")
    public ResponseEntity<?> scan(@PathVariable String id, @Valid @RequestBody ScanRequest req) {
        var result = scanService.requestScan(id, req.targetId(), req.category(), req.mode(), CurrentUser.email());
        return ResponseEntity.accepted().body(result);
    }

    @GetMapping("/engagements/{id}/scans")
    public List<ScanRunView> list(@PathVariable String id) {
        return scanService.list(id).stream().map(ScanRunView::of).toList();
    }

    @PostMapping("/scans/{runId}/stop")
    public ScanRunView stop(@PathVariable String runId) {
        return ScanRunView.of(scanService.stop(runId, CurrentUser.email()));
    }
}
