package de.polyas.core3.open.cred;

import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

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
      @ ensures \invariant_for(\result);
      @ assignable \nothing;
      @ determines \result.password \by password;
      @ determines \result.hashedPassword \by \nothing;
      @ determines \result.publicSigningKey \by GROUP.group.generator.value, GROUP.curve.order;
      @*/
    public static GeneratedDataForVoter generateDataForVoter(String voterId,
                                                             final String password) {
        // derive the public credential (voter's public verification key pk_i)
        final ECPoint pubCred = // TODO HERE: Look! // TODO: Make dummy
                Crypto.publicCredentialFromPIN(GROUP, password, voterId);
        final String pubCredHex = Utils.asHexString(GROUP.elementToBytes(pubCred));

        // derive the log-in password (derived password dp_i)
        final String loginPasswordFromMasterPIN = // TODO: Make dummy
                Crypto.loginPasswordFromMasterPIN(GROUP, voterId, password);
        // compute the salted and hashed password (h_i)
        final String salt = newSalt();
        final String hashedPassword =
                Crypto.hashPasswordWithSHA256(loginPasswordFromMasterPIN, salt);
        final String hashedPasswordWithSalt = salt + "-" + hashedPassword;

        return new GeneratedDataForVoter(password, hashedPasswordWithSalt, pubCredHex);
    }

    /**
     * Generates 8 random bytes and returns them as lower case hex string.
     */
    /*@ public normal_behavior
      @ assignable \nothing;
      @ determines \result \by \nothing;
      @*/
    public static String newSalt() {
        final byte[] b = new byte[8];
        RANDOM.nextBytes(b);
        return Utils.asHexString(b).toLowerCase();
    }

    /*@ public normal_behavior
      @ requires b.length == 8;
      @ assignable b[*];
      @ determines \result \by \nothing;
      @*/
    public static String newSalt(byte[] b) {
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
