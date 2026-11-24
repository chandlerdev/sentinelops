package com.sentinelops.service.logic;

import com.sentinelops.config.AppProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Runs "npm audit" on the SERVER itself (not in Docker, and never against the target's own network) in a
 * throwaway temp folder holding only the uploaded package-lock.json plus a minimal package.json. Captures
 * the FULL stdout to a file rather than a capped tail, since the JSON report can be large.
 */
@Component
public class RealNpmAuditExecutor implements NpmAuditExecutor {

    private static final int MAX_OUTPUT_BYTES = 5_000_000;
    private final AppProperties props;

    public RealNpmAuditExecutor(AppProperties props) {
        this.props = props;
    }

    @Override
    public String run(String packageLockJson) throws Exception {
        Path dir = Files.createTempDirectory("sentinelops-npm-audit-");
        try {
            Files.writeString(dir.resolve("package.json"), "{\"name\":\"sentinelops-audit-target\",\"version\":\"0.0.0\"}",
                    StandardCharsets.UTF_8);
            Files.writeString(dir.resolve("package-lock.json"), packageLockJson, StandardCharsets.UTF_8);

            Path outFile = dir.resolve("audit-output.json");
            ProcessBuilder pb = new ProcessBuilder(List.of(props.getScan().getEngine().getNpmBinary(), "audit",
                    "--package-lock-only", "--json"));
            pb.directory(dir.toFile());
            pb.redirectOutput(outFile.toFile());
            pb.redirectErrorStream(true);
            Process p = pb.start();
            boolean done = p.waitFor(props.getScan().getEngine().getNpmAuditTimeoutSeconds(), TimeUnit.SECONDS);
            if (!done) {
                p.destroyForcibly();
                throw new IOException("npm audit timed out after " + props.getScan().getEngine().getNpmAuditTimeoutSeconds() + "s");
            }
            // npm audit exits non-zero (usually 1) whenever it FINDS vulnerabilities - that is success, not a failure.
            // Only treat it as broken if there is no readable JSON output at all.
            byte[] raw = Files.exists(outFile) ? Files.readAllBytes(outFile) : new byte[0];
            if (raw.length == 0) {
                throw new IOException("npm audit produced no output (exit code " + p.exitValue() + ")");
            }
            int len = Math.min(raw.length, MAX_OUTPUT_BYTES);
            return new String(raw, 0, len, StandardCharsets.UTF_8);
        } finally {
            deleteRecursively(dir);
        }
    }

    private static void deleteRecursively(Path dir) {
        try (var stream = Files.walk(dir)) {
            stream.sorted((a, b) -> b.compareTo(a)).forEach(p -> {
                try { Files.deleteIfExists(p); } catch (IOException ignored) { /* best effort */ }
            });
        } catch (IOException ignored) { /* best effort */ }
    }
}
