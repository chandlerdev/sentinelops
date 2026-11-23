package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.repository.TargetRepository;
import com.sentinelops.repository.TargetVerificationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/** Ownership verification: DNS TXT, HTTP file, manual IP approval, expiry and SSRF protection. */
class VerificationServiceTest {

    private AppProperties props;
    private final Map<String, List<String>> dns = new HashMap<>();
    private final List<String> txtRecords = new ArrayList<>();
    private final Map<String, String> files = new HashMap<>();
    private final List<String> fetchedUrls = new ArrayList<>();
    private final AtomicReference<TargetVerification> saved = new AtomicReference<>();

    private TargetVerificationRepository verifications;
    private TargetRepository targets;
    private AccessService access;
    private VerificationService service;
    private Target domainTarget;
    private Target ipTarget;

    @BeforeEach
    void setUp() {
        props = new AppProperties();
        dns.put("example.com", List.of("93.184.216.34"));

        HostResolver resolver = host -> {
            List<String> ips = dns.get(host);
            if (ips == null) throw new UnknownHostException(host);
            List<InetAddress> out = new ArrayList<>();
            for (String ip : ips) out.add(InetAddress.getByName(ip));
            return out;
        };
        TxtLookup txt = name -> new ArrayList<>(txtRecords);
        HttpTokenFetcher http = url -> {
            fetchedUrls.add(url);
            return Optional.ofNullable(files.get(url));
        };

        verifications = mock(TargetVerificationRepository.class);
        when(verifications.save(any())).thenAnswer(i -> {
            saved.set(i.getArgument(0));
            return i.getArgument(0);
        });
        when(verifications.findFirstByTargetIdAndStatusOrderByCreatedAtDesc(eq("t1"), eq(ChallengeStatus.PENDING)))
                .thenAnswer(i -> saved.get() != null && saved.get().getStatus() == ChallengeStatus.PENDING
                        ? Optional.of(saved.get()) : Optional.empty());
        when(verifications.findByTargetIdAndStatus(any(), any())).thenReturn(List.of());

        targets = mock(TargetRepository.class);
        access = mock(AccessService.class);
        domainTarget = new Target("t1", "e1", TargetKind.DOMAIN, "example.com", "tester");
        ipTarget = new Target("t2", "e1", TargetKind.IP, "93.184.216.40", "tester");
        when(access.requireTarget("t1")).thenReturn(domainTarget);
        when(access.requireTarget("t2")).thenReturn(ipTarget);

        service = new VerificationService(verifications, targets, new ScopeValidator(props, resolver), txt, http,
                mock(AuditService.class), access, props);
    }

    @Test
    void dnsChallengeSucceedsWhenTheTxtRecordHasTheToken() {
        var started = service.start("t1", VerificationMethod.DNS_TXT, "tester");
        assertEquals("_sentinelops-challenge.example.com", started.instructions().recordName());
        String value = started.instructions().recordValue();
        assertTrue(value.startsWith("sentinelops-verify="));

        txtRecords.add("v=spf1 -all");
        txtRecords.add(value);
        var checked = service.check("t1", "tester");

        assertEquals(ChallengeStatus.VERIFIED, checked.verification().getStatus());
        assertEquals(TargetStatus.VERIFIED, domainTarget.getVerificationStatus());
        assertTrue(domainTarget.isVerifiedAt(Instant.now()));
        assertTrue(domainTarget.getVerificationExpiresAt().isAfter(Instant.now().plusSeconds(86400 * 29)));
    }

    @Test
    void dnsChallengeStaysPendingWithTheWrongToken() {
        service.start("t1", VerificationMethod.DNS_TXT, "tester");
        txtRecords.add("sentinelops-verify=not-the-token");
        var checked = service.check("t1", "tester");

        assertEquals(ChallengeStatus.PENDING, checked.verification().getStatus());
        assertFalse(domainTarget.isVerifiedAt(Instant.now()));
    }

    @Test
    void expiredChallengeCannotBeCompleted() {
        props.getVerification().setChallengeHours(0); // token is already expired when checked
        var started = service.start("t1", VerificationMethod.DNS_TXT, "tester");
        txtRecords.add(started.instructions().recordValue());

        var checked = service.check("t1", "tester");
        assertEquals(ChallengeStatus.EXPIRED, checked.verification().getStatus());
        assertFalse(domainTarget.isVerifiedAt(Instant.now()));
    }

    @Test
    void httpFileChallengeSucceedsWithTheToken() {
        var started = service.start("t1", VerificationMethod.HTTP_FILE, "tester");
        files.put("https://example.com/.well-known/sentinelops-verify.txt", started.instructions().fileContent());

        var checked = service.check("t1", "tester");
        assertEquals(ChallengeStatus.VERIFIED, checked.verification().getStatus());
        assertTrue(domainTarget.isVerifiedAt(Instant.now()));
    }

    @Test
    void httpFileWithWrongContentFails() {
        service.start("t1", VerificationMethod.HTTP_FILE, "tester");
        files.put("https://example.com/.well-known/sentinelops-verify.txt", "something else");
        files.put("http://example.com/.well-known/sentinelops-verify.txt", "something else");

        var checked = service.check("t1", "tester");
        assertEquals(ChallengeStatus.PENDING, checked.verification().getStatus());
        assertFalse(domainTarget.isVerifiedAt(Instant.now()));
    }

    @Test
    void httpVerificationNeverConnectsToAnInternalAddress() {
        dns.put("example.com", List.of("10.0.0.7")); // domain points inside the network (SSRF attempt)
        var started = service.start("t1", VerificationMethod.HTTP_FILE, "tester");
        files.put("https://example.com/.well-known/sentinelops-verify.txt", started.instructions().fileContent());

        var checked = service.check("t1", "tester");
        assertEquals(ChallengeStatus.PENDING, checked.verification().getStatus());
        assertTrue(checked.verification().getDetail().startsWith("Refused"));
        assertTrue(fetchedUrls.isEmpty(), "no HTTP request may be made to a forbidden address");
    }

    @Test
    void domainsCannotUseManualApprovalAndIpsCannotUseDns() {
        assertThrows(IllegalArgumentException.class, () ->
                service.recordManualApproval("t1", "Owner", "owner@x.com", "Net Team", "TICKET-1", null, "manager"));
        assertThrows(IllegalArgumentException.class, () ->
                service.start("t2", VerificationMethod.DNS_TXT, "tester"));
    }

    @Test
    void ipOwnershipIsRecordedThroughManualApproval() {
        var v = service.recordManualApproval("t2", "Jordan Lee", "jordan@client.com", "Network Team",
                "EMAIL-2026-11-18", "approved by phone and email", "manager");
        assertEquals(ChallengeStatus.VERIFIED, v.getStatus());
        assertEquals("Network Team", v.getNetworkAckBy());
        assertTrue(ipTarget.isVerifiedAt(Instant.now()));
    }

    @Test
    void checkWithoutAPendingChallengeFails() {
        assertThrows(IllegalStateException.class, () -> service.check("t1", "tester"));
    }
}
