package de.polyas.core3.open.cred;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

import de.polyas.core3.open.crypto.basic.Hashes;
import de.polyas.core3.open.crypto.basic.Utils;
import de.polyas.core3.open.crypto.groups.ECGroup;

/**
 * Collection of cryptographic functions used to generate the credentials.
 */
public final class Crypto {

    /**
     * Set of characters used in passwords.
     */
    public static final String BASE_32_CHARACTERS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    public static final SecureRandom SECURE_RANDOM = Utils.getInstanceStrong();
    public static final MessageDigest SHA_256_DIGEST = getSha256Digest();

    private Crypto() {}

    public static MessageDigest getSha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public static MessageDigest getSha512Digest() {
        try {
            return MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    /**
     * Generates a random password, represented as a sequence of base-32
     * characters, with 80 bits of entropy. The password will be of form
     * `xxxx.xxxx.xxxx.xxxx` where `x` is a base32 character (on of [base32Characters]).
     */
    public static String randomCredential80() {
        return randomBase32String(4) + "."
            + randomBase32String(4) + "."
            + randomBase32String(4) + "."
            + randomBase32String(4);
    }

    /**
     * Generates a random string of given length consisting of base32 characters.
     */
    private static String randomBase32String(int len) {
        final byte[] bytes = new byte[len];
        SECURE_RANDOM.nextBytes(bytes);
        final StringBuilder sb = new StringBuilder();
        for (byte b: bytes) {
            sb.append(BASE_32_CHARACTERS.charAt((b) & 0x1f));
        }
        return sb.toString();
    }

    /**
     * Derives the public credential from given input.
     *
     * @param group the used cyclic group
     * @param password voter's password
     * @param voterId voter's identifier
     * @return The public credential of the voter
     */
    /*@ public normal_behavior
      @ requires \static_invariant_for(BigInteger);
      @ requires \invariant_for(group);
      @ requires \static_invariant_for(Hashes);
      @ requires 0 <= Hashes.currentIndex && Hashes.currentIndex < Hashes.VALUES.length;
      @ ensures Hashes.currentIndex == \old(Hashes.currentIndex) + 1;
      @ ensures \fresh(\result) && \fresh(\result.*) && \typeof(\result) == \type(ECPoint);
      @ assignable Hashes.currentIndex;
      @ determines \result \by \nothing \new_objects \result;
      @ determines \result.value \by group.group.generator.value, group.curve.order,
      @     Hashes.currentIndex, (\seq_def int i; 0; Hashes.VALUES.length; Hashes.VALUES[i].value);
      @*/
    public static /*@helper@*/ ECPoint publicCredentialFromPIN(ECGroup group, String password, String voterId) {
        final BigInteger sk = Hashes.uniformHash(group.order(), password, voterId, null);
        return group.pow(group.generator(), sk);
    }

    /**
     * Derives log-in password (derived password) from the given master PIN (master voter password).
     *
     * @param group the used cyclic group
     * @param voterId voter's identifier
     * @param password voter's password
     * @return The log-in password (derived password) of the voter
     *
     */
    /*@ public normal_behavior
      @ requires \static_invariant_for(java.math.BigInteger);
      @ requires \invariant_for(group);
      @ requires \static_invariant_for(Hashes);
      @ requires 0 <= Hashes.currentIndex && Hashes.currentIndex < Hashes.VALUES.length;
      @ ensures Hashes.currentIndex == \old(Hashes.currentIndex) + 1;
      @ ensures \fresh(\result) && \typeof(\result) == \type(String);
      @ assignable Hashes.currentIndex;
      @ determines \result \by \nothing \new_objects \result;
      @*/
    public static /*@helper@*/ String loginPasswordFromMasterPIN(ECGroup group, String voterId,
                                                    String password) {
        final BigInteger skPrime = Hashes.uniformHash(group.order(), "derive-password",
                                                      password, voterId);
        final ECPoint dk = group.pow(group.generator(), skPrime);
        return Utils.asHexString(group.asBytes(dk));
    }

    /**
     * Computes the SHA256 digest of the given salt concatenated with base.
     */
    /*@ public normal_behavior
      @ ensures \fresh(\result) && \typeof(\result) == \type(String);
      @ assignable \nothing;
      @ determines \result \by \nothing \new_objects \result;
      @*/
    public static String hashPasswordWithSHA256(String password, String salt) {
        return sha256(salt + password);
    }

    /*@ public normal_behavior
      @ ensures \fresh(\result) && \typeof(\result) == \type(String);
      @ assignable \nothing;
      @ determines \result \by \nothing \new_objects \result;
      @*/
    private static String sha256(String input) {
        return Utils.asHexString(SHA_256_DIGEST.digest(input.getBytes()));
    }
}
