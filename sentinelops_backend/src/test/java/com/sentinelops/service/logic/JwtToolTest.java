package com.sentinelops.service.logic;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class JwtToolTest {

    private static String b64(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static String jwt(String headerJson, String payloadJson) {
        return b64(headerJson) + "." + b64(payloadJson) + ".signature-bytes-not-real-base64url";
    }

    @Test
    void recognisesAWellFormedJwtAndRejectsEverythingElse() {
        assertTrue(JwtTool.looksLikeJwt(jwt("{\"alg\":\"HS256\"}", "{\"sub\":\"u1\"}")));
        assertFalse(JwtTool.looksLikeJwt(null));
        assertFalse(JwtTool.looksLikeJwt(""));
        assertFalse(JwtTool.looksLikeJwt("not-a-jwt"));
        assertFalse(JwtTool.looksLikeJwt("abc.def")); // only 2 parts
        assertFalse(JwtTool.looksLikeJwt("session=abc; HttpOnly")); // a cookie, not a token
    }

    @Test
    void algNoneKeepsThePayloadAndDropsTheSignature() {
        String token = jwt("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", "{\"sub\":\"u1\",\"role\":\"user\"}");
        String forged = JwtTool.toAlgNone(token);
        String[] parts = forged.split("\\.", -1);
        assertEquals(3, parts.length);
        assertEquals("", parts[2], "the signature must be empty");

        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        assertTrue(headerJson.contains("\"none\""));
        // payload is untouched
        assertEquals(token.split("\\.")[1], parts[1]);
    }

    @Test
    void tamperingFlipsABooleanPrivilegeClaimAndLeavesTheSignatureBytesAlone() {
        String token = jwt("{\"alg\":\"HS256\"}", "{\"sub\":\"u1\",\"isAdmin\":false}");
        var result = JwtTool.tamperPrivilegeClaim(token);
        assertNotNull(result);
        assertEquals("isAdmin", result.claimChanged());
        String[] parts = result.token().split("\\.", -1);
        assertEquals(token.split("\\.")[0], parts[0], "header is unchanged");
        assertEquals(token.split("\\.")[2], parts[2], "the original (now invalid) signature is kept as-is");
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        assertTrue(payloadJson.contains("\"isAdmin\":true"));
    }

    @Test
    void tamperingFlipsATextualRoleClaim() {
        String token = jwt("{\"alg\":\"HS256\"}", "{\"role\":\"user\"}");
        var result = JwtTool.tamperPrivilegeClaim(token);
        assertNotNull(result);
        assertEquals("role", result.claimChanged());
        String payloadJson = new String(Base64.getUrlDecoder().decode(result.token().split("\\.")[1]), StandardCharsets.UTF_8);
        assertTrue(payloadJson.contains("\"role\":\"admin\""));
    }

    @Test
    void returnsNullWhenNoRecognisableClaimExists() {
        String token = jwt("{\"alg\":\"HS256\"}", "{\"sub\":\"u1\",\"exp\":123}");
        assertNull(JwtTool.tamperPrivilegeClaim(token));
    }
}
