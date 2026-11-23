package com.sentinelops.service.scanner;

import com.sentinelops.entity.ScanMode;
import com.sentinelops.entity.TargetKind;

import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Everything a scanner is allowed to know about one run. Built ONLY through {@link #of}, which re-validates every
 * value that will end up in a container command line. The values are passed as separate argv elements (never
 * through a shell), and none of them can start with '-', so they cannot be read as options.
 * The authentication header value is a secret: it is never part of toString() and never goes on a command line.
 */
public record ScanContext(
        String runId,
        TargetKind kind,
        String host,
        String url,
        int port,
        boolean lab,
        ScanMode mode,
        List<String> addresses,
        String headerName,
        String headerValue,
        String openApiUrl,
        String authHeaderName,
        String authHeaderValue) {

    private static final Pattern RUN_ID = Pattern.compile("^[0-9a-fA-F-]{36}$");
    private static final Pattern DOMAIN = Pattern.compile(
            "^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$");
    private static final Pattern IP_OR_CIDR = Pattern.compile("^[0-9a-fA-F:.]{2,45}(/[0-9]{1,3})?$");
    private static final Pattern IP_LITERAL = Pattern.compile("^[0-9a-fA-F:.]{2,45}$");
    private static final Pattern HEADER_NAME = Pattern.compile("^[A-Za-z][A-Za-z0-9-]{0,40}$");
    private static final Pattern HEADER_VALUE = Pattern.compile("^[A-Za-z0-9/._-]{1,100}$");
    private static final Pattern AUTH_VALUE = Pattern.compile("^[\\x21-\\x7E]([\\x20-\\x7E]{0,1998}[\\x21-\\x7E])?$");
    private static final Pattern URL_FORBIDDEN = Pattern.compile("[\\s\"'`\\\\<>;|&$(){}\\[\\]^]");

    /** Headers a client-supplied credential may not set: they would change how the request is routed or framed. */
    static final Set<String> FORBIDDEN_AUTH_HEADERS = Set.of(
            "host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer",
            "proxy-authorization", "proxy-connection", "x-forwarded-for", "x-forwarded-host", "forwarded");

    public static ScanContext of(String runId, TargetKind kind, String host, String baseUrl, boolean lab,
                                 ScanMode mode, List<String> addresses, String headerName, String headerValue) {
        return of(runId, kind, host, baseUrl, lab, mode, addresses, headerName, headerValue, null, null, null);
    }

    public static ScanContext of(String runId, TargetKind kind, String host, String baseUrl, boolean lab,
                                 ScanMode mode, List<String> addresses, String headerName, String headerValue,
                                 String openApiUrl, String authName, String authValue) {
        require(runId != null && RUN_ID.matcher(runId).matches(), "invalid run id");
        require(kind != null, "missing target kind");
        require(host != null, "missing host");
        if (kind == TargetKind.DOMAIN) {
            require(DOMAIN.matcher(host).matches(), "unsafe host");
        } else {
            require(IP_OR_CIDR.matcher(host).matches(), "unsafe address");
        }
        require(HEADER_NAME.matcher(headerName == null ? "" : headerName).matches(), "unsafe header name");
        require(HEADER_VALUE.matcher(headerValue == null ? "" : headerValue).matches(), "unsafe header value");
        require(addresses != null && addresses.stream().allMatch(a -> IP_LITERAL.matcher(a).matches()),
                "unsafe resolved address");

        String url = null;
        int port = 443;
        String api = null;
        if (kind != TargetKind.CIDR) {
            url = baseUrl != null && !baseUrl.isBlank() ? baseUrl.trim() : "https://" + host;
            URI u = checkedUrl(url, host);
            port = u.getPort() > 0 ? u.getPort() : ("https".equals(u.getScheme()) ? 443 : 80);
            if (openApiUrl != null && !openApiUrl.isBlank()) {
                api = openApiUrl.trim();
                checkedUrl(api, host);
            }
        }

        String an = null;
        String av = null;
        if (authName != null && !authName.isBlank()) {
            require(HEADER_NAME.matcher(authName).matches(), "unsafe credential header name");
            require(!FORBIDDEN_AUTH_HEADERS.contains(authName.toLowerCase()), "credential header not allowed");
            require(!authName.equalsIgnoreCase(headerName), "credential header clashes with the scan marker");
            require(authValue != null && AUTH_VALUE.matcher(authValue).matches(), "unsafe credential value");
            an = authName;
            av = authValue;
        }
        return new ScanContext(runId, kind, host, url, port, lab, mode, List.copyOf(addresses), headerName,
                headerValue, api, an, av);
    }

    private static URI checkedUrl(String url, String host) {
        require(url.length() <= 512 && !URL_FORBIDDEN.matcher(url).find(), "unsafe url");
        URI u;
        try {
            u = URI.create(url);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Scan input refused: unsafe url");
        }
        require("http".equals(u.getScheme()) || "https".equals(u.getScheme()), "url scheme must be http or https");
        require(u.getUserInfo() == null, "url must not contain credentials");
        String uh = u.getHost() == null ? "" : u.getHost().toLowerCase();
        require(uh.equals(host.toLowerCase()), "url host differs from the authorized target");
        return u;
    }

    private static void require(boolean ok, String message) {
        if (!ok) throw new IllegalArgumentException("Scan input refused: " + message);
    }

    /** True when the URL uses https. */
    public boolean https() { return url != null && url.startsWith("https://"); }

    public String headerLine() { return headerName + ": " + headerValue; }

    public boolean authenticated() { return authHeaderName != null; }

    /** Never prints the credential. */
    @Override
    public String toString() {
        return "ScanContext[run=" + runId + ", host=" + host + ", mode=" + mode
                + ", authenticated=" + authenticated() + "]";
    }
}
