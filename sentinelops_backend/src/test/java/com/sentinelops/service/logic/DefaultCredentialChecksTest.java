package com.sentinelops.service.logic;

import com.sentinelops.entity.SessionType;
import com.sentinelops.entity.TestIdentity;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Only a real session from a candidate pair counts; never guessed from a response that merely looks different. */
class DefaultCredentialChecksTest {

    private static TestIdentity shape() {
        return new TestIdentity("i1", "t1", "Admin login", "https://app.example.com/login", "email", "password",
                "ignored@example.com", "ignored-enc", "token", SessionType.HEADER_BEARER, null, null, "POST", "tess");
    }

    @Test
    void aCandidatePairThatLogsInIsVulnerable() {
        LoginFlowRunner login = mock(LoginFlowRunner.class);
        when(login.attempt(any(), any())).thenReturn(new LoginFlowRunner.LoginOutcome(false, 401, false, null, "no"));
        when(login.attempt(argThat(i -> i != null && i.getUsername().equals("admin")), eq("admin")))
                .thenReturn(new LoginFlowRunner.LoginOutcome(true, 200, true, "tok", "ok"));

        var result = new DefaultCredentialChecks(login).check(shape());
        assertEquals(DefaultCredentialChecks.Verdict.VULNERABLE, result.verdict());
        assertTrue(result.description().contains("admin"));
    }

    @Test
    void noCandidateWorkingIsNotVulnerable() {
        LoginFlowRunner login = mock(LoginFlowRunner.class);
        when(login.attempt(any(), any())).thenReturn(new LoginFlowRunner.LoginOutcome(false, 401, false, null, "no"));

        var result = new DefaultCredentialChecks(login).check(shape());
        assertEquals(DefaultCredentialChecks.Verdict.NOT_VULNERABLE, result.verdict());
    }

    @Test
    void stopsAtTheFirstWorkingPairAndDoesNotKeepGuessing() {
        LoginFlowRunner login = mock(LoginFlowRunner.class);
        // the very first candidate (admin/admin) already works
        when(login.attempt(any(), eq("admin"))).thenReturn(new LoginFlowRunner.LoginOutcome(true, 200, true, "tok", "ok"));
        when(login.attempt(any(), argThat(pw -> !"admin".equals(pw)))).thenReturn(new LoginFlowRunner.LoginOutcome(false, 401, false, null, "no"));

        new DefaultCredentialChecks(login).check(shape());
        verify(login, times(1)).attempt(any(), any());
    }

    @Test
    void neverUsesTheIdentitysOwnStoredUsername() {
        LoginFlowRunner login = mock(LoginFlowRunner.class);
        when(login.attempt(any(), any())).thenReturn(new LoginFlowRunner.LoginOutcome(false, 401, false, null, "no"));

        new DefaultCredentialChecks(login).check(shape());
        verify(login, never()).attempt(argThat(i -> i.getUsername().equals("ignored@example.com")), any());
    }
}
