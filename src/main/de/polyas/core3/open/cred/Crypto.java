package de.polyas.core3.open.cred;

import de.polyas.core3.open.crypto.basic.Hashes;
import de.polyas.core3.open.crypto.basic.Utils;
import de.polyas.core3.open.crypto.groups.ECGroup;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Collection of cryptographic functions used to generate the credentials.
 */
public class Crypto {
    /**
     * Set of characters used in passwords
     */
    private static final String base32Characters = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private static final SecureRandom secureRandom = Utils.getInstanceStrong();
    private static final MessageDigest sha256digest = getSha256Digest();

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
     * Generates a random string of given length consisting of base32 characters
     */
    private static String randomBase32String(int len) {
        final byte[] bytes = new byte[len];
        secureRandom.nextBytes(bytes);
        final StringBuilder sb = new StringBuilder();
        for (byte b: bytes) {
            sb.append(base32Characters.charAt(((int)b) & 0x1f));
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
    public static ECPoint publicCredentialFromPIN(ECGroup group, String password, String voterId) {
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
    public static String loginPasswordFromMasterPIN(ECGroup group, String voterId, String password) {
        final BigInteger skPrime = Hashes.uniformHash(group.order(), "derive-password", password, voterId);
        final ECPoint dk = group.pow(group.generator(), skPrime);
        return Utils.asHexString(group.asBytes(dk));
    }

    /**
     * Computes the SHA256 digest of the given salt concatenated with base
     */
    public static String hashPasswordWithSHA256(String password, String salt) {
        return sha256(salt + password);
    }

    private static String sha256(String input) {
        return Utils.asHexString(sha256digest.digest(input.getBytes()));
    }
}
