package de.polyas.core3.open.cred;

import de.polyas.core3.open.crypto.basic.Utils;
import de.polyas.core3.open.crypto.groups.ECGroup;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Utility for generating voters' passwords and derived data.
 *
 * <p>It implements the procedure described in Appendix A.3 of the
 * document "Polyas 3.0 E-voting System, Variant for the GI 2019 Election".
 */
public final class CredentialGenerator {

    // the cyclic group instance used to generate credentials - elliptic curve group SecP256K1
    private static final ECGroup GROUP = new ECGroup();
    private static final SecureRandom RANDOM = Utils.getInstanceStrong();

    private CredentialGenerator() {}

    /**
     * Generates credentials, including a random password, for a given voter.
     *
     * @param voterId The identifier of the voter
     * @return Generated data for the voter consisting of a random password, hashed password,
     *         and the voter's public signing key (public credential)
     */
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
    public static String newSalt() {
        final byte[] b = new byte[8];
        RANDOM.nextBytes(b);
        return Utils.asHexString(b).toLowerCase();
    }

    /**
     * Data record generated for a voter.
     */
    public static class GeneratedDataForVoter {
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
