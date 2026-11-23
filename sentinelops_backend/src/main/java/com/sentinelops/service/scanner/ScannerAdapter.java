package com.sentinelops.service.scanner;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.ScanCategory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;

/**
 * One scanning tool. An adapter only describes a FIXED command template for its container and how to read the
 * tool's output; it never executes anything itself. The authorization gate has already passed when it is used.
 */
public interface ScannerAdapter {

    long MAX_OUTPUT_BYTES = 20L * 1024 * 1024;

    String id();

    boolean supports(ScanCategory category);

    /** Mode- and target-aware variant. Adapters that only make sense in some situations override this. */
    default boolean supports(ScanCategory category, com.sentinelops.entity.ScanMode mode, ScanContext ctx) {
        return supports(category);
    }

    /** Files (name inside the work dir -> content) holding secrets; written 0600 just before the run, deleted right after. */
    default java.util.Map<String, String> secretFiles(ScanContext ctx) { return java.util.Map.of(); }

    /** Environment variables for the container, taken from our own environment so they never reach a command line. */
    default java.util.Map<String, String> secretEnv(ScanContext ctx) { return java.util.Map.of(); }

    String image(AppProperties.Engine engine);

    /** Arguments after the image name (including the program name for images without an entrypoint). */
    List<String> command(ScanContext ctx);

    /** Folder inside the container where the work directory is mounted. */
    default String containerOutDir() { return "/out"; }

    /** Output file (inside the work dir) that proves the tool produced a result. */
    String outputFile();

    default boolean acceptsExit(int code) { return code == 0; }

    List<NormalizedFinding> parse(Path outDir, ScanContext ctx) throws IOException;

    // ---- helpers shared by adapters ----

    Pattern TAGS = Pattern.compile("<[^>]*>");

    static String stripHtml(String s) {
        if (s == null) return null;
        String t = TAGS.matcher(s).replaceAll(" ")
                .replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
                .replace("&quot;", "\"").replace("&#39;", "'");
        return t.replaceAll("\\s+", " ").strip();
    }

    static byte[] readCapped(Path file) throws IOException {
        if (!Files.exists(file)) throw new IOException("Tool produced no output file " + file.getFileName());
        if (Files.size(file) > MAX_OUTPUT_BYTES) throw new IOException("Tool output too large");
        return Files.readAllBytes(file);
    }
}
