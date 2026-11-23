package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.Target;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

import com.sentinelops.util.Cidr;

/**
 * Decides whether a network address / target may ever be touched by the platform.
 *
 * Blocked by default: loopback, private (RFC 1918), CGNAT, link-local (incl. the 169.254.169.254 cloud
 * metadata address), multicast, reserved, IPv6 local ranges, every address of this server and the
 * addresses listed in configuration. The ONLY exception is the controlled lab: a target flagged "lab",
 * allowlisted by host, resolving inside the configured lab CIDRs, with the lab feature enabled.
 */
@Component
public class ScopeValidator {

    private static final List<Cidr> BLOCKED = List.of(
            // IPv4
            Cidr.parse("0.0.0.0/8"), Cidr.parse("10.0.0.0/8"), Cidr.parse("100.64.0.0/10"),
            Cidr.parse("127.0.0.0/8"), Cidr.parse("169.254.0.0/16"), Cidr.parse("172.16.0.0/12"),
            Cidr.parse("192.0.0.0/24"), Cidr.parse("192.0.2.0/24"), Cidr.parse("192.168.0.0/16"),
            Cidr.parse("198.18.0.0/15"), Cidr.parse("198.51.100.0/24"), Cidr.parse("203.0.113.0/24"),
            Cidr.parse("224.0.0.0/4"), Cidr.parse("240.0.0.0/4"),
            // IPv6
            Cidr.parse("::/128"), Cidr.parse("::1/128"), Cidr.parse("fc00::/7"), Cidr.parse("fe80::/10"),
            Cidr.parse("ff00::/8"), Cidr.parse("64:ff9b::/96"), Cidr.parse("2001:db8::/32"));

    /** Result of a scope check. {@code addresses} lists what the target resolved to. */
    public record Check(boolean allowed, String reason, List<String> addresses) {
        static Check ok(List<String> addresses) { return new Check(true, null, addresses); }
        static Check deny(String reason, List<String> addresses) { return new Check(false, reason, addresses); }
    }

    private final AppProperties props;
    private final HostResolver resolver;

    public ScopeValidator(AppProperties props, HostResolver resolver) {
        this.props = props;
        this.resolver = resolver;
    }

    /** Static policy: is this address in a never-scan range (before any lab exception)? */
    public boolean isBlockedAddress(InetAddress a) {
        for (Cidr c : BLOCKED) {
            if (c.contains(a)) return true;
        }
        if (isConfiguredBlocked(a)) return true;
        return isLocalInterface(a);
    }

    private boolean isConfiguredBlocked(InetAddress a) {
        for (String entry : props.getScan().getBlockedAddresses()) {
            if (entry == null || entry.isBlank()) continue;
            try {
                if (Cidr.parse(entry).contains(a)) return true;
            } catch (IllegalArgumentException ignored) { /* bad config entry is ignored */ }
        }
        return false;
    }

    private boolean isLocalInterface(InetAddress a) {
        try {
            Enumeration<NetworkInterface> nics = NetworkInterface.getNetworkInterfaces();
            while (nics != null && nics.hasMoreElements()) {
                Enumeration<InetAddress> addrs = nics.nextElement().getInetAddresses();
                while (addrs.hasMoreElements()) {
                    if (addrs.nextElement().equals(a)) return true;
                }
            }
        } catch (Exception ignored) { /* cannot enumerate: other rules still apply */ }
        return false;
    }

    private List<Cidr> labCidrs() {
        List<Cidr> out = new ArrayList<>();
        for (String s : props.getScan().getLab().getCidrs()) {
            try {
                out.add(Cidr.parse(s));
            } catch (IllegalArgumentException ignored) { /* ignore bad config entry */ }
        }
        return out;
    }

    public boolean isLabHost(String host) {
        if (host == null) return false;
        String h = host.toLowerCase(Locale.ROOT);
        return props.getScan().getLab().getHosts().stream()
                .anyMatch(x -> x != null && x.trim().toLowerCase(Locale.ROOT).equals(h));
    }

    private boolean inLabNetwork(InetAddress a) {
        return labCidrs().stream().anyMatch(c -> c.contains(a));
    }

    /** Address-level verdict. {@code labTarget} enables the lab exception for blocked-but-lab addresses only. */
    public Check checkAddress(InetAddress a, boolean labTarget) {
        String text = a.getHostAddress();
        if (!isBlockedAddress(a)) return Check.ok(List.of(text));
        if (labTarget && props.getScan().getLab().isEnabled() && inLabNetwork(a) && !isLocalInterface(a)) {
            return Check.ok(List.of(text));
        }
        return Check.deny("Address " + text + " is in a blocked range (private, loopback, link-local, "
                + "metadata, reserved or this server). Only the approved lab network is exempt.", List.of(text));
    }

    /** Resolves (fresh DNS) and validates a target. Called at registration and again at every scan start. */
    public Check checkTarget(Target t) {
        switch (t.getKind()) {
            case DOMAIN:
                return checkDomain(t);
            case IP:
                return checkAddress(Cidr.parseLiteral(t.getValue()), t.isLab());
            case CIDR:
                return checkCidr(t);
            default:
                return Check.deny("Unsupported target kind", List.of());
        }
    }

    private Check checkDomain(Target t) {
        String host = t.getValue();
        if (t.isLab()) {
            if (!props.getScan().getLab().isEnabled()) return Check.deny("Lab scanning is disabled on this server.", List.of());
            if (!isLabHost(host)) return Check.deny("Host '" + host + "' is not on the lab allowlist.", List.of());
        }
        List<InetAddress> addresses;
        try {
            addresses = resolver.resolve(host);
        } catch (UnknownHostException e) {
            return Check.deny("Host '" + host + "' does not resolve in DNS.", List.of());
        }
        if (addresses.isEmpty()) return Check.deny("Host '" + host + "' has no addresses.", List.of());

        List<String> texts = addresses.stream().map(InetAddress::getHostAddress).collect(Collectors.toList());
        for (InetAddress a : addresses) {
            Check c = checkAddress(a, t.isLab());
            if (!c.allowed()) return Check.deny("Host '" + host + "' resolves to a forbidden address. " + c.reason(), texts);
        }
        return Check.ok(texts);
    }

    private Check checkCidr(Target t) {
        Cidr c;
        try {
            c = Cidr.parse(t.getValue());
        } catch (IllegalArgumentException e) {
            return Check.deny("Invalid CIDR.", List.of());
        }
        int min = c.isIpv4() ? props.getScan().getMinIpv4Prefix() : props.getScan().getMinIpv6Prefix();
        if (c.prefix() < min) {
            return Check.deny("Range is too large (smallest allowed prefix is /" + min + ").", List.of());
        }
        boolean labOk = t.isLab() && props.getScan().getLab().isEnabled()
                && labCidrs().stream().anyMatch(c::isInside);
        if (labOk) return Check.ok(List.of(t.getValue()));
        for (Cidr b : BLOCKED) {
            if (b.overlaps(c)) return Check.deny("Range overlaps a blocked (private/reserved) network.", List.of());
        }
        for (String entry : props.getScan().getBlockedAddresses()) {
            try {
                if (Cidr.parse(entry).overlaps(c)) return Check.deny("Range contains a blocked address.", List.of());
            } catch (IllegalArgumentException ignored) { /* ignore bad config entry */ }
        }
        return Check.ok(List.of(t.getValue()));
    }
}
