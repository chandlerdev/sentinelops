package com.sentinelops.service.scanner;

import com.sentinelops.entity.ScanCategory;
import com.sentinelops.entity.ScanMode;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * ZAP API scan from an imported OpenAPI definition. The API scan always runs ZAP's active rules, so it is only
 * offered in ACTIVE mode. "-O host" forces every request to the authorized host even if the definition lists
 * other servers.
 */
@Component
public class ZapApiAdapter extends ZapAdapter {

    @Override public String id() { return "zap-api"; }

    @Override public boolean supports(ScanCategory c) { return false; }

    @Override
    public boolean supports(ScanCategory c, ScanMode mode, ScanContext ctx) {
        return c == ScanCategory.API && mode == ScanMode.ACTIVE && ctx.openApiUrl() != null;
    }

    @Override
    public List<String> command(ScanContext ctx) {
        List<String> c = new ArrayList<>(List.of("zap-api-scan.py",
                "-t", ctx.openApiUrl(), "-f", "openapi", "-O", ctx.host(),
                "-J", outputFile(), "-I", "-T", "25"));
        c.add("-z");
        c.add(markerConfig(ctx));
        return c;
    }
}
