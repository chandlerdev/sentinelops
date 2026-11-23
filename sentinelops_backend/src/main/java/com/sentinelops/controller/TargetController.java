package com.sentinelops.controller;

import com.sentinelops.dto.TargetDtos.*;
import com.sentinelops.service.ScanService;
import com.sentinelops.service.TargetService;
import com.sentinelops.service.VerificationService;
import com.sentinelops.util.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/** Targets of an engagement, their ownership verification, and the dry-run authorization-gate check. */
@RestController
@RequestMapping("/api/engagements/{engagementId}/targets")
public class TargetController {

    private final TargetService targets;
    private final VerificationService verification;
    private final ScanService scans;

    public TargetController(TargetService targets, VerificationService verification, ScanService scans) {
        this.targets = targets;
        this.verification = verification;
        this.scans = scans;
    }

    @GetMapping
    public List<TargetView> list(@PathVariable String engagementId) {
        return targets.list(engagementId).stream().map(TargetView::from).toList();
    }

    @PostMapping
    public ResponseEntity<TargetView> register(@PathVariable String engagementId, @Valid @RequestBody TargetRequest req) {
        var t = targets.register(engagementId, req.value(), req.baseUrl(), req.label(), req.technology(),
                req.lab(), CurrentUser.email());
        return ResponseEntity.status(201).body(TargetView.from(t));
    }

    @GetMapping("/{targetId}")
    public TargetView get(@PathVariable String engagementId, @PathVariable String targetId) {
        return TargetView.from(targets.get(targetId));
    }

    @GetMapping("/{targetId}/verifications")
    public List<VerificationView> history(@PathVariable String engagementId, @PathVariable String targetId) {
        return verification.history(targetId).stream().map(VerificationView::from).toList();
    }

    @PostMapping("/{targetId}/verification")
    public ResponseEntity<VerificationView> start(@PathVariable String engagementId, @PathVariable String targetId,
                                                  @Valid @RequestBody StartVerificationRequest req) {
        var c = verification.start(targetId, req.method(), CurrentUser.email());
        return ResponseEntity.status(201).body(VerificationView.from(c));
    }

    @PostMapping("/{targetId}/verification/check")
    public VerificationView check(@PathVariable String engagementId, @PathVariable String targetId) {
        return VerificationView.from(verification.check(targetId, CurrentUser.email()));
    }

    @PostMapping("/{targetId}/verification/manual")
    public ResponseEntity<VerificationView> manual(@PathVariable String engagementId, @PathVariable String targetId,
                                                   @Valid @RequestBody ManualApprovalRequest req) {
        var v = verification.recordManualApproval(targetId, req.approverName(), req.approverContact(),
                req.networkAckBy(), req.evidenceRef(), req.notes(), CurrentUser.email());
        return ResponseEntity.status(201).body(VerificationView.from(v));
    }

    /** Dry run: evaluates the gate exactly as a real scan would, without starting a scan. */
    @PostMapping("/{targetId}/gate-check")
    public GateCheckView gateCheck(@PathVariable String engagementId, @PathVariable String targetId,
                                   @Valid @RequestBody GateCheckRequest req) {
        var r = scans.checkGate(engagementId, targetId, req.category(), req.mode(), CurrentUser.email());
        return new GateCheckView(r.allowed(), r.reason(), r.resolvedAddresses(), r.effectiveMode());
    }
}
