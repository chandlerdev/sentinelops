package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.Target;
import com.sentinelops.entity.TargetCredential;
import com.sentinelops.entity.TargetKind;
import com.sentinelops.repository.TargetCredentialRepository;
import com.sentinelops.repository.TargetRepository;
import com.sentinelops.exception.NotFoundException;
import com.sentinelops.util.SecretBox;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.time.Instant;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Credentials for authenticated scans (one header per target) and the OpenAPI definition of a target.
 * The value is encrypted at rest, never returned by the API, never logged, and only decrypted by the scan worker.
 */
@Service
public class CredentialService {

    private static final Pattern NAME = Pattern.compile("^[A-Za-z][A-Za-z0-9-]{0,40}$");
    private static final Pattern VALUE = Pattern.compile("^[\\x21-\\x7E]([\\x20-\\x7E]{0,1998}[\\x21-\\x7E])?$");
    private static final Pattern URL_FORBIDDEN = Pattern.compile("[\\s\"'`\\\\<>;|&$(){}\\[\\]^]");

    public record Header(String name, String value) {
        @Override public String toString() { return "Header[" + name + ", value hidden]"; }
    }

    public record CredentialInfo(String headerName, String createdBy, Instant createdAt) {}

    private final TargetCredentialRepository creds;
    private final TargetRepository targets;
    private final AccessService access;
    private final AuditService audit;
    private final AppProperties props;

    public CredentialService(TargetCredentialRepository creds, TargetRepository targets, AccessService access,
                             AuditService audit, AppProperties props) {
        this.creds = creds;
        this.targets = targets;
        this.access = access;
        this.audit = audit;
        this.props = props;
    }

    private Target target(String engagementId, String targetId) {
        access.requireEngagement(engagementId);
        Target t = targets.findById(targetId).orElseThrow(() -> new NotFoundException("Target not found"));
        if (!t.getEngagementId().equals(engagementId)) throw new NotFoundException("Target not found");
        return t;
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public CredentialInfo set(String engagementId, String targetId, String headerName, String value, String actor) {
        Target t = target(engagementId, targetId);
        if (t.getKind() == TargetKind.CIDR) throw new IllegalArgumentException("A range cannot hold a credential.");
        if (headerName == null || !NAME.matcher(headerName).matches()
                || com.sentinelops.service.scanner.ScanContextAccess.forbidden(headerName)) {
            throw new IllegalArgumentException("That header name is not allowed.");
        }
        if (value == null || !VALUE.matcher(value).matches()) {
            throw new IllegalArgumentException("The value must be 1-2000 printable ASCII characters.");
        }
        SecretBox box = new SecretBox(props.getSecurity().getSecretKey()); // fails closed without a key
        TargetCredential c = new TargetCredential(targetId, headerName, box.encrypt(value), actor);
        creds.save(c);
        audit.record(actor, "credential.set", "Target", targetId, "header=" + headerName); // never the value
        return new CredentialInfo(c.getHeaderName(), c.getCreatedBy(), c.getCreatedAt());
    }

    @Transactional(readOnly = true)
    public Optional<CredentialInfo> info(String engagementId, String targetId) {
        target(engagementId, targetId);
        return creds.findById(targetId).map(c -> new CredentialInfo(c.getHeaderName(), c.getCreatedBy(), c.getCreatedAt()));
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public void delete(String engagementId, String targetId, String actor) {
        target(engagementId, targetId);
        if (creds.existsById(targetId)) {
            creds.deleteById(targetId);
            audit.record(actor, "credential.deleted", "Target", targetId, "");
        }
    }

    /** For the scan worker only. */
    @Transactional(readOnly = true)
    public Optional<Header> decrypt(String targetId) {
        return creds.findById(targetId).map(c ->
                new Header(c.getHeaderName(), new SecretBox(props.getSecurity().getSecretKey()).decrypt(c.getEncValue())));
    }

    /** Sets or clears the OpenAPI definition URL (must be on the target's own host). */
    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public Target setOpenApi(String engagementId, String targetId, String url, String actor) {
        Target t = target(engagementId, targetId);
        if (url == null || url.isBlank()) {
            t.setOpenApiUrl(null);
        } else {
            String u = url.trim();
            if (t.getKind() == TargetKind.CIDR) throw new IllegalArgumentException("A range has no API definition.");
            if (u.length() > 512 || URL_FORBIDDEN.matcher(u).find()) throw new IllegalArgumentException("Unsafe URL.");
            URI uri;
            try { uri = URI.create(u); } catch (IllegalArgumentException e) { throw new IllegalArgumentException("Invalid URL."); }
            if (!("http".equals(uri.getScheme()) || "https".equals(uri.getScheme())) || uri.getUserInfo() != null
                    || uri.getHost() == null || !uri.getHost().equalsIgnoreCase(t.getValue())) {
                throw new IllegalArgumentException("The API definition must be an http(s) URL on the target's own host.");
            }
            t.setOpenApiUrl(u);
        }
        targets.save(t);
        audit.record(actor, "target.openapi", "Target", targetId, "url=" + t.getOpenApiUrl());
        return t;
    }
}
