package com.sentinelops.controller;

import com.sentinelops.dto.AuthorizationDtos.AuthorizationRequest;
import com.sentinelops.dto.AuthorizationDtos.AuthorizationView;
import com.sentinelops.dto.AuthorizationDtos.DecisionRequest;
import com.sentinelops.service.AuthorizationService;
import com.sentinelops.util.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/** Written-authorization workflow. Route access is role-gated in SecurityConfig and again in the service. */
@RestController
@RequestMapping("/api")
public class AuthorizationController {

    private final AuthorizationService authorizations;

    public AuthorizationController(AuthorizationService authorizations) {
        this.authorizations = authorizations;
    }

    @GetMapping("/engagements/{engagementId}/authorizations")
    public List<AuthorizationView> list(@PathVariable String engagementId) {
        return authorizations.list(engagementId).stream().map(AuthorizationView::from).toList();
    }

    @PostMapping("/engagements/{engagementId}/authorizations")
    public ResponseEntity<AuthorizationView> create(@PathVariable String engagementId,
                                                    @Valid @RequestBody AuthorizationRequest req) {
        var draft = new AuthorizationService.Draft(req.title(), req.approverName(), req.approverContact(),
                req.emergencyContact(), req.permittedMethods(), req.excludedAssets(), req.windowStart(),
                req.windowEnd(), req.allowActive(), req.evidenceRef(), req.targetIds(), req.allowAuthenticated());
        var a = authorizations.create(engagementId, draft, CurrentUser.email());
        return ResponseEntity.status(201).body(AuthorizationView.from(a));
    }

    @PostMapping("/authorizations/{id}/submit")
    public AuthorizationView submit(@PathVariable String id) {
        return AuthorizationView.from(authorizations.submit(id, CurrentUser.email()));
    }

    @PostMapping("/authorizations/{id}/approve")
    public AuthorizationView approve(@PathVariable String id, @Valid @RequestBody(required = false) DecisionRequest req) {
        return AuthorizationView.from(authorizations.approve(id, note(req), CurrentUser.email()));
    }

    @PostMapping("/authorizations/{id}/reject")
    public AuthorizationView reject(@PathVariable String id, @Valid @RequestBody(required = false) DecisionRequest req) {
        return AuthorizationView.from(authorizations.reject(id, note(req), CurrentUser.email()));
    }

    @PostMapping("/authorizations/{id}/revoke")
    public AuthorizationView revoke(@PathVariable String id, @Valid @RequestBody(required = false) DecisionRequest req) {
        return AuthorizationView.from(authorizations.revoke(id, note(req), CurrentUser.email()));
    }

    private static String note(DecisionRequest req) {
        return req == null ? null : req.note();
    }
}
