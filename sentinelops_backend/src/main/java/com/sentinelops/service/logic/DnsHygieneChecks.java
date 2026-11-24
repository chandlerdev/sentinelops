package com.sentinelops.service.logic;

import com.sentinelops.entity.Severity;
import com.sentinelops.service.TxtLookup;
import org.springframework.stereotype.Component;

import javax.naming.NameNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Phase 5 of the logic-testing engine (NET-09: DNS misconfiguration - email spoofing hygiene). Pure DNS
 * reads, same as the ownership-verification TXT check: no traffic reaches the target's application at all,
 * so this runs under the plain gate (no ACTIVE / authenticated-testing requirement), like a passive scan.
 */
@Component
public class DnsHygieneChecks {

    public enum Verdict { VULNERABLE, NOT_VULNERABLE, NEEDS_MANUAL_REVIEW }

    public record Result(String checkId, String title, Verdict verdict, Severity severity, String location,
                         String description, String remediation) {
        static Result review(String checkId, String title, String location, String why) {
            return new Result(checkId, title, Verdict.NEEDS_MANUAL_REVIEW, Severity.INFORMATIONAL, location, why, null);
        }
        static Result clean(String checkId, String title, String location) {
            return new Result(checkId, title, Verdict.NOT_VULNERABLE, Severity.INFORMATIONAL, location, null, null);
        }
    }

    private final TxtLookup dns;

    public DnsHygieneChecks(TxtLookup dns) {
        this.dns = dns;
    }

    /** NXDOMAIN / no-such-name means "no record published" - a real, checkable fact, not a lookup failure. */
    private List<String> safeLookup(String name) throws Exception {
        try {
            return dns.lookup(name);
        } catch (NameNotFoundException ex) {
            return List.of();
        }
    }

    public List<Result> check(String domain) {
        List<Result> out = new ArrayList<>();
        out.add(checkSpf(domain));
        out.add(checkDmarc(domain));
        return out;
    }

    private Result checkSpf(String domain) {
        String checkId = "NET-09a", title = "SPF record missing or overly permissive";
        List<String> records;
        try {
            records = safeLookup(domain);
        } catch (Exception ex) {
            return Result.review(checkId, title, domain, "Could not look up TXT records for " + domain + ": " + ex.getClass().getSimpleName());
        }
        String spf = records.stream().filter(r -> r.toLowerCase(Locale.ROOT).startsWith("v=spf1")).findFirst().orElse(null);
        if (spf == null) {
            return new Result(checkId, title, Verdict.VULNERABLE, Severity.MEDIUM, domain,
                    "No SPF TXT record was found for " + domain + ". Without one, anyone can forge email that appears to come from this domain.",
                    "Publish an SPF TXT record listing your legitimate mail servers, ending in \"-all\" (hard fail).");
        }
        if (spf.toLowerCase(Locale.ROOT).contains("+all")) {
            return new Result(checkId, title, Verdict.VULNERABLE, Severity.HIGH, domain,
                    "The SPF record explicitly allows ANY server to send mail as this domain (\"+all\"): " + spf,
                    "Replace \"+all\" with \"-all\" after listing every legitimate sending server/service.");
        }
        return Result.clean(checkId, title, domain);
    }

    private Result checkDmarc(String domain) {
        String checkId = "NET-09b", title = "DMARC record missing or not enforced";
        String name = "_dmarc." + domain;
        List<String> records;
        try {
            records = safeLookup(name);
        } catch (Exception ex) {
            return Result.review(checkId, title, name, "Could not look up TXT records for " + name + ": " + ex.getClass().getSimpleName());
        }
        String dmarc = records.stream().filter(r -> r.toLowerCase(Locale.ROOT).startsWith("v=dmarc1")).findFirst().orElse(null);
        if (dmarc == null) {
            return new Result(checkId, title, Verdict.VULNERABLE, Severity.MEDIUM, name,
                    "No DMARC TXT record was found at " + name + ". Without one, spoofed email claiming to be from this "
                            + "domain is not reported or blocked by receiving mail servers.",
                    "Publish a DMARC record at " + name + " with a policy of at least \"p=quarantine\" (ideally \"p=reject\").");
        }
        if (dmarc.toLowerCase(Locale.ROOT).contains("p=none")) {
            return new Result(checkId, title, Verdict.VULNERABLE, Severity.LOW, name,
                    "The DMARC policy is \"p=none\" (monitor only): spoofed mail is reported but not blocked. " + dmarc,
                    "Move the policy to \"p=quarantine\" or \"p=reject\" once monitoring reports look clean.");
        }
        return Result.clean(checkId, title, name);
    }
}
