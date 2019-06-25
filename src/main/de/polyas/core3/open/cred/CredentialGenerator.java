package de.polyas.core3.open.cred;

import de.polyas.core3.open.crypto.groups.ECGroup;
import de.polyas.core3.open.crypto.basic.Utils;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Utility for generating voters' passwords and derived data.
 *
 * It implements the procedure described in Appendix A.3 of the
 * document "Polyas 3.0 E-voting System, Variant for the GI 2019 Election".
 */
class CredentialGenerator {

	// the cyclic group instance used to generate credentials - elliptic curve group SecP256K1
    private static final ECGroup group = new ECGroup();
    private static final SecureRandom random = Utils.getInstanceStrong();

    /**
     * Generates credentials, including a random password, for a given voter.
     *
     * @param voterId The identifier of the voter
     * @return Generated data for the voter consisting of a random password, hashed password,
     *         and the voter's public signing key (public credential)
     */
    public static GeneratedDataForVoter generateDataForVoter(String voterId) {
        // generate a password with 80 bits of entropy
        final String password = Crypto.randomCredential80();

        // derive the public credential (voter's public verification key pk_i)
        final ECPoint pubCred = // TODO HERE: Look! // TODO: Make dummy
                Crypto.publicCredentialFromPIN(group, password, voterId);
        final String pubCredHex = Utils.asHexString(group.elementToBytes(pubCred));

        // derive the log-in password (derived password dp_i)
        final String loginPasswordFromMasterPIN = // TODO: Make dummy
                Crypto.loginPasswordFromMasterPIN(group, voterId, password);
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
        random.nextBytes(b);
        return Utils.asHexString(b).toLowerCase();
    }

    /**
     * Data record generated for a voter.
     *
     * @param password  Voters (master) password; to be send (via the distribution facility) to the voter
     * @param hashedPassword  Salted and hashed password (including the salt); to be sent to POLYAS
     * @param publicSigningKey  Public voter's credential; to be send to POLYAS and published on the registration board
     */
    public static class GeneratedDataForVoter {
        final String password; // TODO HERE: xx
        final String hashedPassword;
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
