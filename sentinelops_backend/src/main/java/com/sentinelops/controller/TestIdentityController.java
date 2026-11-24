package com.sentinelops.controller;

import com.sentinelops.dto.TestIdentityDtos.TestIdentityRequest;
import com.sentinelops.service.LogicTestService;
import com.sentinelops.service.TestIdentityService;
import com.sentinelops.util.CurrentUser;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Phase 0 of the logic-testing engine: stored test accounts on a target's own login (see
 * PENTEST_COVERAGE_PLAN.md). Passwords are write-only, like scan credentials.
 */
@RestController
@RequestMapping("/api/engagements/{id}/targets/{tid}/identities")
public class TestIdentityController {

    private final TestIdentityService identities;
    private final LogicTestService logic;

    public TestIdentityController(TestIdentityService identities, LogicTestService logic) {
        this.identities = identities;
        this.logic = logic;
    }

    @GetMapping
    public List<TestIdentityService.View> list(@PathVariable String id, @PathVariable String tid) {
        return identities.list(id, tid);
    }

    @PostMapping
    public ResponseEntity<TestIdentityService.View> create(@PathVariable String id, @PathVariable String tid,
                                                           @Valid @RequestBody TestIdentityRequest r) {
        var v = identities.create(id, tid, r.label(), r.loginUrl(), r.usernameField(), r.passwordField(),
                r.username(), r.password(), r.tokenPath(), r.sessionType(), r.probeUrl(), r.logoutUrl(),
                r.logoutMethod(), CurrentUser.email());
        return ResponseEntity.status(201).body(v);
    }

    @DeleteMapping("/{identityId}")
    public ResponseEntity<Void> delete(@PathVariable String id, @PathVariable String tid, @PathVariable String identityId) {
        identities.delete(id, tid, identityId, CurrentUser.email());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{identityId}/test-login")
    public TestIdentityService.LoginTestResult testLogin(@PathVariable String id, @PathVariable String tid,
                                                         @PathVariable String identityId) {
        return identities.testLogin(id, tid, identityId, CurrentUser.email());
    }

    /** Phase 1: AUTH-11 (JWT manipulation) and AUTH-12 (logout session reuse). See PENTEST_COVERAGE_PLAN.md. */
    @PostMapping("/{identityId}/auth-checks")
    public LogicTestService.RunResult authChecks(@PathVariable String id, @PathVariable String tid,
                                                 @PathVariable String identityId) {
        return logic.runAuthChecks(id, tid, identityId, CurrentUser.email());
    }

    /** Phase 5 (NET-07): tries well-known default credentials against this identity's login shape. */
    @PostMapping("/{identityId}/default-creds-check")
    public LogicTestService.RunResult defaultCredsCheck(@PathVariable String id, @PathVariable String tid,
                                                        @PathVariable String identityId) {
        return logic.runDefaultCredentialCheck(id, tid, identityId, CurrentUser.email());
    }
}
