package com.sentinelops.service;

import com.sentinelops.entity.SystemSetting;
import com.sentinelops.repository.SystemSettingRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Administrator-controlled global settings. Active scanning is OFF unless an ADMIN switches it on. */
@Service
public class SettingsService {

    public static final String ACTIVE_SCANNING = "active_scanning_enabled";

    private final SystemSettingRepository repo;
    private final AuditService audit;

    public SettingsService(SystemSettingRepository repo, AuditService audit) {
        this.repo = repo;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public boolean isActiveScanningEnabled() {
        return repo.findById(ACTIVE_SCANNING).map(s -> "true".equalsIgnoreCase(s.getValue())).orElse(false);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public void setActiveScanningEnabled(boolean enabled, String actor) {
        SystemSetting s = repo.findById(ACTIVE_SCANNING)
                .orElseGet(() -> new SystemSetting(ACTIVE_SCANNING, "false", actor));
        s.update(Boolean.toString(enabled), actor);
        repo.save(s);
        audit.record(actor, "settings.active_scanning", "SystemSetting", ACTIVE_SCANNING, "enabled=" + enabled);
    }
}
