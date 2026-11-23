package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.Target;
import com.sentinelops.entity.TargetKind;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

/** Security tests: localhost / private / metadata protection, DNS-based evasion, the lab exception, range limits. */
class ScopeValidatorTest {

    private AppProperties props;
    /** Fake DNS: host -> addresses. Tests may change it between calls to simulate DNS changes. */
    private final Map<String, List<String>> dns = new ConcurrentHashMap<>();
    private ScopeValidator validator;

    @BeforeEach
    void setUp() {
        props = new AppProperties();
        dns.clear();
        HostResolver fake = host -> {
            List<String> ips = dns.get(host);
            if (ips == null) throw new UnknownHostException(host);
            List<InetAddress> out = new ArrayList<>();
            for (String ip : ips) out.add(InetAddress.getByName(ip)); // literals: no real DNS
            return out;
        };
        validator = new ScopeValidator(props, fake);
    }

    private static InetAddress ip(String s) throws Exception {
        return InetAddress.getByName(s);
    }

    private static Target domain(String host, boolean lab) {
        Target t = new Target("t", "e", TargetKind.DOMAIN, host, "tester");
        t.setLab(lab);
        return t;
    }

    private static Target ipTarget(String address, boolean lab) {
        Target t = new Target("t", "e", TargetKind.IP, address, "tester");
        t.setLab(lab);
        return t;
    }

    private static Target cidr(String range, boolean lab) {
        Target t = new Target("t", "e", TargetKind.CIDR, range, "tester");
        t.setLab(lab);
        return t;
    }

    @Test
    void blocksLoopbackPrivateLinkLocalMetadataAndReservedAddresses() throws Exception {
        for (String a : new String[]{
                "127.0.0.1", "127.1.2.3", "10.0.0.5", "172.16.0.1", "172.31.255.254", "192.168.1.10",
                "169.254.169.254", "169.254.1.1", "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255",
                "::1", "fe80::1", "fc00::1", "fd12:3456::1", "::ffff:10.0.0.1", "::ffff:127.0.0.1"}) {
            assertTrue(validator.isBlockedAddress(ip(a)), a + " must be blocked");
        }
    }

    @Test
    void allowsOrdinaryPublicAddresses() throws Exception {
        for (String a : new String[]{"8.8.8.8", "1.1.1.1", "172.32.0.1", "172.15.255.255", "2606:4700:4700::1111"}) {
            assertFalse(validator.isBlockedAddress(ip(a)), a + " must be allowed");
        }
    }

    @Test
    void blocksTheConfiguredServerAddress() throws Exception {
        props.getScan().setBlockedAddresses(List.of("198.51.101.0/24", "93.184.216.34"));
        assertTrue(validator.isBlockedAddress(ip("93.184.216.34")));
        assertTrue(validator.isBlockedAddress(ip("198.51.101.9")));
        assertFalse(validator.isBlockedAddress(ip("93.184.216.35")));
    }

    @Test
    void domainResolvingToPublicAddressIsAllowed() {
        dns.put("app.example.com", List.of("93.184.216.34"));
        var c = validator.checkTarget(domain("app.example.com", false));
        assertTrue(c.allowed());
        assertEquals(List.of("93.184.216.34"), c.addresses());
    }

    @Test
    void domainResolvingToPrivateOrLoopbackIsDenied() {
        dns.put("internal.example.com", List.of("10.1.2.3"));
        dns.put("local.example.com", List.of("127.0.0.1"));
        dns.put("meta.example.com", List.of("169.254.169.254"));
        assertFalse(validator.checkTarget(domain("internal.example.com", false)).allowed());
        assertFalse(validator.checkTarget(domain("local.example.com", false)).allowed());
        assertFalse(validator.checkTarget(domain("meta.example.com", false)).allowed());
    }

    @Test
    void oneBadAddressAmongPublicOnesDeniesTheWholeTarget() {
        dns.put("mixed.example.com", List.of("93.184.216.34", "10.0.0.9"));
        assertFalse(validator.checkTarget(domain("mixed.example.com", false)).allowed());
    }

    @Test
    void dnsChangeBetweenChecksIsDetected() {
        dns.put("shifty.example.com", List.of("93.184.216.34"));
        assertTrue(validator.checkTarget(domain("shifty.example.com", false)).allowed());
        dns.put("shifty.example.com", List.of("192.168.0.20")); // record now points inside the network
        assertFalse(validator.checkTarget(domain("shifty.example.com", false)).allowed());
    }

    @Test
    void unresolvableDomainIsDenied() {
        assertFalse(validator.checkTarget(domain("nothing.example.com", false)).allowed());
    }

    @Test
    void ipAndCidrTargets() {
        assertTrue(validator.checkTarget(ipTarget("8.8.8.8", false)).allowed());
        assertFalse(validator.checkTarget(ipTarget("192.168.1.1", false)).allowed());
        assertTrue(validator.checkTarget(cidr("198.51.101.0/24", false)).allowed());
        assertFalse(validator.checkTarget(cidr("10.0.0.0/24", false)).allowed());
        assertFalse(validator.checkTarget(cidr("8.8.0.0/16", false)).allowed(), "/16 is too large");
        assertFalse(validator.checkTarget(cidr("0.0.0.0/0", false)).allowed());
    }

    @Test
    void rangeOverlappingServerAddressIsDenied() {
        props.getScan().setBlockedAddresses(List.of("198.51.101.50"));
        assertFalse(validator.checkTarget(cidr("198.51.101.0/24", false)).allowed());
    }

    // ---- lab exception ----

    private void enableLab() {
        props.getScan().getLab().setEnabled(true);
        props.getScan().getLab().setCidrs(List.of("172.28.0.0/24"));
        props.getScan().getLab().setHosts(List.of("juice-shop"));
    }

    @Test
    void labTargetMayUsePrivateAddressInsideTheLabNetworkOnly() {
        enableLab();
        dns.put("juice-shop", List.of("172.28.0.5"));
        assertTrue(validator.checkTarget(domain("juice-shop", true)).allowed());
    }

    @Test
    void sameAddressIsDeniedForANonLabTarget() {
        enableLab();
        dns.put("juice-shop", List.of("172.28.0.5"));
        assertFalse(validator.checkTarget(domain("juice-shop", false)).allowed());
    }

    @Test
    void labExceptionDoesNotCoverOtherPrivateAddresses() {
        enableLab();
        dns.put("juice-shop", List.of("10.0.0.5")); // private but NOT in the lab CIDR
        assertFalse(validator.checkTarget(domain("juice-shop", true)).allowed());
        assertFalse(validator.checkTarget(ipTarget("192.168.1.1", true)).allowed());
        assertFalse(validator.checkTarget(ipTarget("127.0.0.1", true)).allowed());
    }

    @Test
    void labHostMustBeAllowlisted() {
        enableLab();
        dns.put("other-lab", List.of("172.28.0.6"));
        assertFalse(validator.checkTarget(domain("other-lab", true)).allowed());
    }

    @Test
    void labIsOffUnlessEnabled() {
        props.getScan().getLab().setCidrs(List.of("172.28.0.0/24"));
        props.getScan().getLab().setHosts(List.of("juice-shop"));
        dns.put("juice-shop", List.of("172.28.0.5"));
        assertFalse(validator.checkTarget(domain("juice-shop", true)).allowed());
    }

    @Test
    void labIpAndRangeInsideLabNetworkAreAllowedButWiderRangesAreNot() {
        enableLab();
        assertTrue(validator.checkTarget(ipTarget("172.28.0.7", true)).allowed());
        assertTrue(validator.checkTarget(cidr("172.28.0.0/25", true)).allowed());
        assertFalse(validator.checkTarget(cidr("172.28.0.0/16", true)).allowed());
        assertFalse(validator.checkTarget(cidr("172.28.0.0/24", false)).allowed());
    }
}
