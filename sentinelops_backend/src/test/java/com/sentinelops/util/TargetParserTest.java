package com.sentinelops.util;

import com.sentinelops.entity.TargetKind;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TargetParserTest {

    @Test
    void detectsDomainIpAndCidr() {
        assertEquals(TargetKind.DOMAIN, TargetParser.parse("Example.COM", false).kind());
        assertEquals("example.com", TargetParser.parse("Example.COM", false).value());
        assertEquals(TargetKind.IP, TargetParser.parse("203.0.113.7", false).kind());
        assertEquals(TargetKind.CIDR, TargetParser.parse("198.51.100.0/24", false).kind());
    }

    @Test
    void urlIsReducedToItsHost() {
        var p = TargetParser.parse("https://App.Example.com/some/path?x=1", false);
        assertEquals(TargetKind.DOMAIN, p.kind());
        assertEquals("app.example.com", p.value());
    }

    @Test
    void rejectsCredentialsPortsWildcardsAndOtherSchemes() {
        assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("https://user:pw@example.com/", false));
        assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("ftp://example.com", false));
        assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("example.com:8080", false));
        assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("*.example.com", false));
        assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("exa mple.com", false));
        assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("", false));
        assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("999.1.1.1", false));
    }

    @Test
    void singleLabelHostOnlyWhenAllowed() {
        assertThrows(IllegalArgumentException.class, () -> TargetParser.parse("juice-shop", false));
        assertEquals("juice-shop", TargetParser.parse("juice-shop", true).value());
    }

    @Test
    void ipv6LiteralIsAnIp() {
        assertEquals(TargetKind.IP, TargetParser.parse("2606:4700:4700::1111", false).kind());
    }
}
