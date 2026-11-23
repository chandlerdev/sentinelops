package com.sentinelops.util;

import com.sentinelops.entity.TargetKind;

import java.net.URI;
import java.util.Locale;
import java.util.regex.Pattern;

/** Turns user input into a validated, normalized target. Pure functions, no network access. */
public final class TargetParser {

    private static final Pattern DOMAIN = Pattern.compile(
            "^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$");
    private static final Pattern SINGLE_LABEL = Pattern.compile("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$");

    public record Parsed(TargetKind kind, String value) {}

    private TargetParser() {}

    /** Detects the kind from the text: CIDR if it has '/', IP if a literal, otherwise a domain / URL host. */
    public static Parsed parse(String input, boolean allowSingleLabelHost) {
        if (input == null || input.isBlank()) throw new IllegalArgumentException("Target value is required");
        String raw = input.trim();

        if (raw.contains("://")) {
            raw = hostOfUrl(raw);
        }
        if (raw.contains("/") ) {
            // CIDR (a URL was already reduced to its host above)
            Cidr c = Cidr.parse(raw);
            return new Parsed(TargetKind.CIDR, raw.toLowerCase(Locale.ROOT));
        }
        if (Cidr.isIpLiteral(raw)) {
            return new Parsed(TargetKind.IP, Cidr.parseLiteral(raw).getHostAddress());
        }
        return new Parsed(TargetKind.DOMAIN, normalizeDomain(raw, allowSingleLabelHost));
    }

    public static String normalizeDomain(String input, boolean allowSingleLabelHost) {
        String d = input.trim().toLowerCase(Locale.ROOT);
        if (d.endsWith(".")) d = d.substring(0, d.length() - 1);
        if (d.contains(":") || d.contains("@") || d.contains(" ") || d.contains("*")) {
            throw new IllegalArgumentException("Invalid domain name (no ports, wildcards, credentials or spaces)");
        }
        boolean ok = DOMAIN.matcher(d).matches() || (allowSingleLabelHost && SINGLE_LABEL.matcher(d).matches());
        if (!ok) throw new IllegalArgumentException("Invalid domain name: " + input);
        return d;
    }

    /** Extracts the host from an http(s) URL; rejects userinfo and non-http schemes. */
    public static String hostOfUrl(String url) {
        try {
            URI u = URI.create(url.trim());
            String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
            if (!scheme.equals("http") && !scheme.equals("https")) {
                throw new IllegalArgumentException("Only http(s) URLs are allowed");
            }
            if (u.getUserInfo() != null) throw new IllegalArgumentException("URLs with credentials are not allowed");
            String host = u.getHost();
            if (host == null || host.isBlank()) throw new IllegalArgumentException("URL has no host");
            return host.toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid URL");
        }
    }
}
