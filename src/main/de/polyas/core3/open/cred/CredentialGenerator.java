package de.polyas.core3.open.cred;

import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

import de.polyas.core3.open.crypto.basic.Hashes;
import de.polyas.core3.open.crypto.basic.Utils;
import de.polyas.core3.open.crypto.groups.ECGroup;

/**
 * Utility for generating voters' passwords and derived data.
 *
 * <p>It implements the procedure described in Appendix A.3 of the
 * document "Polyas 3.0 E-voting System, Variant for the GI 2019 Election".
 */
public final class CredentialGenerator {

    // the cyclic group instance used to generate credentials - elliptic curve group SecP256K1
    public static final ECGroup GROUP = new ECGroup();
    public static final SecureRandom RANDOM = Utils.getInstanceStrong();

    //@ public static invariant \invariant_for(GROUP);
    //@ public static invariant \invariant_for(RANDOM);

    private CredentialGenerator() {}

    /**
     * Generates credentials, including a random password, for a given voter.
     *
     * @param voterId The identifier of the voter
     * @return Generated data for the voter consisting of a random password, hashed password,
     *         and the voter's public signing key (public credential)
     */
    /*@ public normal_behavior
      @ requires \static_invariant_for(Crypto);
      @ requires \static_invariant_for(java.math.BigInteger);
      @ requires \static_invariant_for(Hashes);
      @ requires Hashes.currentIndex < Hashes.VALUES.length;
      @ ensures Hashes.currentIndex == \old(Hashes.currentIndex) + 1;
      @ ensures \invariant_for(\result);
      @ ensures \fresh(\result) && \fresh(\result.hashedPassword) && \fresh(\result.publicSigningKey)
      @         && \typeof(\result) == \type(GeneratedDataForVoter) && \typeof(\result.hashedPassword) == \type(String) && \typeof(\result.publicSigningKey) == \type(String);
      @ assignable \nothing;
      @ determines \result.hashedPassword, \result.publicSigningKey \by \nothing \new_objects \result.hashedPassword, \result.publicSigningKey;
      @*/
    public static GeneratedDataForVoter generateDataForVoter(String voterId,
                                                             final String password) {
        // derive the public credential (voter's public verification key pk_i)
        final ECPoint pubCred =
                Crypto.publicCredentialFromPIN(GROUP, password, voterId);
        final String pubCredHex = Utils.asHexString(GROUP.elementToBytes(pubCred));

        // derive the log-in password (derived password dp_i)
        final String loginPasswordFromMasterPIN = // TODO: Make dummy
                Crypto.loginPasswordFromMasterPIN(GROUP, voterId, password);
        // compute the salted and hashed password (h_i)
        final String salt = newSalt();
        final String hashedPassword =
                Crypto.hashPasswordWithSHA256(loginPasswordFromMasterPIN, salt);
        final String hashedPasswordWithSalt = append(salt, "-", hashedPassword);

        return new GeneratedDataForVoter(password, hashedPasswordWithSalt, pubCredHex);
    }

    /*@ public normal_behavior // NOTE: UNPROVEN, WE ASSUME THAT THE RESULT OF THE PLUS OPERATOR ON STRINGS DEPENDS ONLY ON THE OPERANDS.
      @ requires true;
      @ ensures \fresh(\result) && \typeof(\result) == \type(String);
      @ assignable \nothing;
      @ determines \result \by \nothing \new_objects \result;
      @ determines \dl_strContent(\result) \by \dl_strContent(s0), \dl_strContent(s1), \dl_strContent(s2);
      @*/
    private /*@helper@*/ static String append(String s0, String s1, String s2) {
        return s0 + s1 + s2;
    }

    /**
     * Generates 8 random bytes and returns them as lower case hex string.
     */
    /*@ public normal_behavior
      @ ensures \fresh(\result) && \typeof(\result) == \type(String);
      @ assignable \nothing;
      @ determines \result \by \nothing \new_objects \result;
      @ determines \dl_strContent(\result) \by \nothing;
      @*/
    public static String newSalt() {
        final byte[] b = new byte[8];
        RANDOM.nextBytes(b);
        return Utils.asHexString(b).toLowerCase();
    }

    /**
     * Data record generated for a voter.
     */
    public static final class GeneratedDataForVoter {
        /**
         * Voters (master) password; to be sent (via the distribution facility) to the voter.
         */
        final String password; // TODO HERE: xx
        /**
         * Salted and hashed password (including the salt); to be sent to POLYAS.
         */
        final String hashedPassword;
        /**
         * Public voter's credential; to be send to POLYAS and published on the registration board.
         */
        final String publicSigningKey;

        public GeneratedDataForVoter(final String password,
                                     final String hashedPassword,
                                     final String publicSigningKey) {
            this.password = password;
            this.hashedPassword = hashedPassword;
            this.publicSigningKey = publicSigningKey;
        }
    }
}
