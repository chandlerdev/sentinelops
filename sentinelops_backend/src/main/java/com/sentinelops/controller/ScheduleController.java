package com.sentinelops.controller;

import com.sentinelops.dto.ScheduleDtos.*;
import com.sentinelops.dto.TargetDtos.TargetView;
import com.sentinelops.service.CredentialService;
import com.sentinelops.service.ScheduleService;
import com.sentinelops.util.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/** Phase 5: schedules, scan credentials and OpenAPI definitions. */
@RestController
@RequestMapping("/api")
public class ScheduleController {

    private final ScheduleService schedules;
    private final CredentialService credentials;

    public ScheduleController(ScheduleService schedules, CredentialService credentials) {
        this.schedules = schedules;
        this.credentials = credentials;
    }

    @GetMapping("/engagements/{id}/schedules")
    public List<ScheduleView> list(@PathVariable String id) {
        return schedules.list(id).stream().map(ScheduleView::from).toList();
    }

    @PostMapping("/engagements/{id}/schedules")
    public ResponseEntity<ScheduleView> create(@PathVariable String id, @Valid @RequestBody ScheduleRequest r) {
        var s = schedules.create(id, r.targetId(), r.category(), r.mode(), r.intervalDays(), r.startAt(), CurrentUser.email());
        return ResponseEntity.status(201).body(ScheduleView.from(s));
    }

    @PutMapping("/schedules/{id}/enabled")
    public ScheduleView enable(@PathVariable String id, @RequestBody EnabledRequest r) {
        return ScheduleView.from(schedules.setEnabled(id, r.enabled(), CurrentUser.email()));
    }

    @DeleteMapping("/schedules/{id}")
    public ResponseEntity<Void> delete(@PathVariable String id) {
        schedules.delete(id, CurrentUser.email());
        return ResponseEntity.noContent().build();
    }

    // ---- authenticated scans: the value is write-only ----

    @PutMapping("/engagements/{id}/targets/{tid}/credential")
    public CredentialService.CredentialInfo setCredential(@PathVariable String id, @PathVariable String tid,
                                                          @Valid @RequestBody CredentialRequest r) {
        return credentials.set(id, tid, r.headerName(), r.value(), CurrentUser.email());
    }

    @GetMapping("/engagements/{id}/targets/{tid}/credential")
    public Map<String, Object> credentialInfo(@PathVariable String id, @PathVariable String tid) {
        var info = credentials.info(id, tid);
        return info.<Map<String, Object>>map(i -> Map.of("present", true, "headerName", i.headerName(),
                "createdBy", i.createdBy(), "createdAt", i.createdAt().toString())).orElse(Map.of("present", false));
    }

    @DeleteMapping("/engagements/{id}/targets/{tid}/credential")
    public ResponseEntity<Void> deleteCredential(@PathVariable String id, @PathVariable String tid) {
        credentials.delete(id, tid, CurrentUser.email());
        return ResponseEntity.noContent().build();
    }

    // ---- OpenAPI definition ----

    @PutMapping("/engagements/{id}/targets/{tid}/openapi")
    public TargetView openApi(@PathVariable String id, @PathVariable String tid, @Valid @RequestBody OpenApiRequest r) {
        return TargetView.from(credentials.setOpenApi(id, tid, r.url(), CurrentUser.email()));
    }
}
