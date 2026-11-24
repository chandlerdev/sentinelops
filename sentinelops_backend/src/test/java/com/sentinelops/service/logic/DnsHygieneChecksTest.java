package com.sentinelops.service.logic;

import com.sentinelops.service.TxtLookup;
import org.junit.jupiter.api.Test;

import javax.naming.NameNotFoundException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Every verdict comes from a real TXT lookup; "no record" (NXDOMAIN) is a fact, never an error. */
class DnsHygieneChecksTest {

    @Test
    void missingSpfIsVulnerable() throws Exception {
        TxtLookup dns = mock(TxtLookup.class);
        when(dns.lookup("app.example.com")).thenReturn(List.of());
        when(dns.lookup("_dmarc.app.example.com")).thenReturn(List.of("v=DMARC1; p=reject"));

        var results = new DnsHygieneChecks(dns).check("app.example.com");
        var spf = results.stream().filter(r -> r.checkId().equals("NET-09a")).findFirst().orElseThrow();
        assertEquals(DnsHygieneChecks.Verdict.VULNERABLE, spf.verdict());
    }

    @Test
    void permissiveSpfIsVulnerable() throws Exception {
        TxtLookup dns = mock(TxtLookup.class);
        when(dns.lookup("app.example.com")).thenReturn(List.of("v=spf1 include:_spf.example.com +all"));
        when(dns.lookup("_dmarc.app.example.com")).thenReturn(List.of("v=DMARC1; p=reject"));

        var results = new DnsHygieneChecks(dns).check("app.example.com");
        var spf = results.stream().filter(r -> r.checkId().equals("NET-09a")).findFirst().orElseThrow();
        assertEquals(DnsHygieneChecks.Verdict.VULNERABLE, spf.verdict());
    }

    @Test
    void aHardFailSpfIsNotVulnerable() throws Exception {
        TxtLookup dns = mock(TxtLookup.class);
        when(dns.lookup("app.example.com")).thenReturn(List.of("v=spf1 include:_spf.example.com -all"));
        when(dns.lookup("_dmarc.app.example.com")).thenReturn(List.of("v=DMARC1; p=reject"));

        var results = new DnsHygieneChecks(dns).check("app.example.com");
        var spf = results.stream().filter(r -> r.checkId().equals("NET-09a")).findFirst().orElseThrow();
        assertEquals(DnsHygieneChecks.Verdict.NOT_VULNERABLE, spf.verdict());
    }

    @Test
    void missingDmarcViaNameNotFoundIsTreatedAsMissingNotAnError() throws Exception {
        TxtLookup dns = mock(TxtLookup.class);
        when(dns.lookup("app.example.com")).thenReturn(List.of("v=spf1 -all"));
        when(dns.lookup("_dmarc.app.example.com")).thenThrow(new NameNotFoundException("no such name"));

        var results = new DnsHygieneChecks(dns).check("app.example.com");
        var dmarc = results.stream().filter(r -> r.checkId().equals("NET-09b")).findFirst().orElseThrow();
        assertEquals(DnsHygieneChecks.Verdict.VULNERABLE, dmarc.verdict());
        assertFalse(dmarc.description().toLowerCase().contains("exception"), "should read as a fact, not an error");
    }

    @Test
    void dmarcPNoneIsVulnerableButLowSeverity() throws Exception {
        TxtLookup dns = mock(TxtLookup.class);
        when(dns.lookup("app.example.com")).thenReturn(List.of("v=spf1 -all"));
        when(dns.lookup("_dmarc.app.example.com")).thenReturn(List.of("v=DMARC1; p=none"));

        var results = new DnsHygieneChecks(dns).check("app.example.com");
        var dmarc = results.stream().filter(r -> r.checkId().equals("NET-09b")).findFirst().orElseThrow();
        assertEquals(DnsHygieneChecks.Verdict.VULNERABLE, dmarc.verdict());
        assertEquals(com.sentinelops.entity.Severity.LOW, dmarc.severity());
    }

    @Test
    void enforcedDmarcIsNotVulnerable() throws Exception {
        TxtLookup dns = mock(TxtLookup.class);
        when(dns.lookup("app.example.com")).thenReturn(List.of("v=spf1 -all"));
        when(dns.lookup("_dmarc.app.example.com")).thenReturn(List.of("v=DMARC1; p=reject"));

        var results = new DnsHygieneChecks(dns).check("app.example.com");
        assertTrue(results.stream().allMatch(r -> r.verdict() == DnsHygieneChecks.Verdict.NOT_VULNERABLE));
    }

    @Test
    void aGenuineLookupFailureIsManualReviewNotAVerdict() throws Exception {
        TxtLookup dns = mock(TxtLookup.class);
        when(dns.lookup(anyString())).thenThrow(new RuntimeException("timeout"));

        var results = new DnsHygieneChecks(dns).check("app.example.com");
        assertTrue(results.stream().allMatch(r -> r.verdict() == DnsHygieneChecks.Verdict.NEEDS_MANUAL_REVIEW));
    }
}
