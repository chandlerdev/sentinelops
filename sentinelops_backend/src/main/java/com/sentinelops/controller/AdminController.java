package com.sentinelops.controller;

import com.sentinelops.dto.AdminDtos.*;
import com.sentinelops.service.AuditService;
import com.sentinelops.service.SettingsService;
import com.sentinelops.service.UserService;
import com.sentinelops.util.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/** Administration: users, global settings (active-scanning switch) and the audit log. */
@RestController
@RequestMapping("/api")
public class AdminController {

    private final UserService users;
    private final SettingsService settings;
    private final AuditService audit;

    public AdminController(UserService users, SettingsService settings, AuditService audit) {
        this.users = users;
        this.settings = settings;
        this.audit = audit;
    }

    @GetMapping("/users")
    public List<UserView> listUsers() {
        return users.list().stream().map(UserView::from).toList();
    }

    @PostMapping("/users")
    public ResponseEntity<UserView> createUser(@Valid @RequestBody UserRequest req) {
        var u = users.create(req.name(), req.email(), req.password(), req.role(), req.clientId(), CurrentUser.email());
        return ResponseEntity.status(201).body(UserView.from(u));
    }

    @GetMapping("/settings")
    public SettingsView getSettings() {
        return new SettingsView(settings.isActiveScanningEnabled());
    }

    @PutMapping("/settings/active-scanning")
    public SettingsView setActiveScanning(@RequestBody ActiveScanningRequest req) {
        settings.setActiveScanningEnabled(req.enabled(), CurrentUser.email());
        return new SettingsView(settings.isActiveScanningEnabled());
    }

    @GetMapping("/audit")
    public List<AuditView> audit(@RequestParam(required = false) String entity,
                                 @RequestParam(required = false) String entityId,
                                 @RequestParam(defaultValue = "100") int limit) {
        return audit.recent(entity, entityId, limit).stream().map(AuditView::from).toList();
    }
}
