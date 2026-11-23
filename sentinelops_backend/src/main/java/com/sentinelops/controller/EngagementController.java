package com.sentinelops.controller;

import com.sentinelops.dto.EngagementDtos.EngagementRequest;
import com.sentinelops.dto.EngagementDtos.EngagementView;
import com.sentinelops.service.EngagementService;
import com.sentinelops.util.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/engagements")
public class EngagementController {

    private final EngagementService engagements;

    public EngagementController(EngagementService engagements) {
        this.engagements = engagements;
    }

    @GetMapping
    public List<EngagementView> list() {
        return engagements.list().stream().map(EngagementView::from).toList();
    }

    @GetMapping("/{id}")
    public EngagementView get(@PathVariable String id) {
        return EngagementView.from(engagements.get(id));
    }

    @PostMapping
    public ResponseEntity<EngagementView> create(@Valid @RequestBody EngagementRequest req) {
        var e = engagements.create(req.name(), req.clientId(), req.environment(),
                req.windowStart(), req.windowEnd(), CurrentUser.email());
        return ResponseEntity.status(201).body(EngagementView.from(e));
    }
}
