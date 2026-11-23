package com.sentinelops.util;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/** AES-256-GCM with a random 12-byte nonce per value. Output: base64(nonce || ciphertext+tag). */
public final class SecretBox {

    private static final SecureRandom RANDOM = new SecureRandom();
    private final SecretKeySpec key;

    /** @param base64Key base64 of exactly 32 bytes; blank or wrong length = refuse to work (fail closed). */
    public SecretBox(String base64Key) {
        if (base64Key == null || base64Key.isBlank()) {
            throw new IllegalStateException("Credential storage is off: set sentinelops.security.secret-key "
                    + "(base64 of 32 random bytes, e.g. 'openssl rand -base64 32').");
        }
        byte[] k;
        try {
            k = Base64.getDecoder().decode(base64Key.trim());
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("sentinelops.security.secret-key is not valid base64.");
        }
        if (k.length != 32) {
            throw new IllegalStateException("sentinelops.security.secret-key must decode to exactly 32 bytes.");
        }
        this.key = new SecretKeySpec(k, "AES");
    }

    public String encrypt(String plain) {
        try {
            byte[] nonce = new byte[12];
            RANDOM.nextBytes(nonce);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
            byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(ByteBuffer.allocate(nonce.length + ct.length).put(nonce).put(ct).array());
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Encryption failed", ex);
        }
    }

    public String decrypt(String encoded) {
        try {
            byte[] all = Base64.getDecoder().decode(encoded);
            if (all.length < 12 + 16) throw new IllegalStateException("Stored credential is corrupt.");
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, all, 0, 12));
            return new String(c.doFinal(all, 12, all.length - 12), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Stored credential cannot be decrypted (wrong key or corrupt).");
        }
    }
}
