package de.polyas.core3.open.crypto.basic;

import de.polyas.core3.open.cred.Crypto;
import java.math.BigInteger;
import java.security.MessageDigest;

public final class Hashes {

    private Hashes() {}

    // Universal context for hashing
    public static class HashCtx {
        private final MessageDigest digest;

        public HashCtx(final MessageDigest digest) {
            this.digest = digest;
        }

        public void feed(String string) {
            digest.update(string.getBytes());
        }

    }

    // Simple use case

    public static byte[] hash512(final String s1, final String s2, final String s3) {
        final HashCtx ctx = new HashCtx(Crypto.getSha512Digest());
        ctx.feed(s1);
        if (s2 != null) {
            ctx.feed(s2);
        }
        if (s3 != null) {
            ctx.feed(s3);
        }
        return ctx.digest.digest();
    }

    /**
     * Computes the uniform hash of the provided data.
     *
     * <p>The usage pattern is
     *
     *   <p>val h = uniformHash(order) {
     *          feed(data1)
     *          ...
     *          feed(dataN)
     *      }
     *
     * <p>The result `h` is computed by digesting (hashing) the provided data
     * (`data1`, ... `dataN`); the result is distributed pseudo-uniformly
     * in the range [0, upperBound).
     *
     * <p>This function implements Algorithm 4 of the documentation for
     * POLYAS 3.0 Verifiable.
     */
    public static BigInteger uniformHash(BigInteger upperBound, final String s1,
                                         final String s2, final String s3) {
        return BigInteger.ZERO; // XXX: Dummy
    }
}
