package com.sentinelops.controller;

import com.sentinelops.dto.FindingDtos.*;
import com.sentinelops.entity.FindingStatus;
import com.sentinelops.entity.Severity;
import com.sentinelops.service.FindingService;
import com.sentinelops.service.ScanService;
import com.sentinelops.util.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class FindingController {

    private final FindingService service;

    public FindingController(FindingService service) {
        this.service = service;
    }

    @GetMapping("/engagements/{id}/findings")
    public List<FindingView> list(@PathVariable String id,
                                  @RequestParam(required = false) Severity severity,
                                  @RequestParam(required = false) FindingStatus status,
                                  @RequestParam(required = false) String tool) {
        return service.list(id, severity, status, tool).stream().map(FindingView::from).toList();
    }

    @GetMapping("/findings/{id}")
    public FindingDetail detail(@PathVariable String id) {
        return service.detail(id);
    }

    @PostMapping("/findings/{id}/validate")
    public FindingView validate(@PathVariable String id, @Valid @RequestBody ValidateRequest req) {
        return FindingView.from(service.validate(id, req.confirm(), req.note(), CurrentUser.email()));
    }

    @PutMapping("/findings/{id}/status")
    public FindingView status(@PathVariable String id, @Valid @RequestBody StatusRequest req) {
        return FindingView.from(service.changeStatus(id, req.status(), req.note(), CurrentUser.email()));
    }

    @PostMapping("/findings/{id}/retest")
    public ResponseEntity<ScanService.ScanRequested> retest(@PathVariable String id) {
        return ResponseEntity.accepted().body(service.requestRetest(id, CurrentUser.email()));
    }

    @GetMapping("/engagements/{id}/dashboard")
    public EngagementDashboard engagementDashboard(@PathVariable String id) {
        return service.engagementDashboard(id);
    }

    @GetMapping("/dashboard")
    public GlobalDashboard dashboard() {
        return service.globalDashboard();
    }
}
