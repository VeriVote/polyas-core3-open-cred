package de.polyas.core3.open.crypto.basic;

import java.math.BigInteger;
import java.security.MessageDigest;

import de.polyas.core3.open.cred.Crypto;

public final class Hashes {

    private Hashes() {}

    // Universal context for hashing
    public static final class HashCtx {
        private final MessageDigest digest;

        //@ public instance invariant \invariant_for(digest);

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

    private /*@spec_public@*/ static int currentIndex;

    private /*@spec_public@*/ static final BigInteger[] VALUES = {
        BigInteger.valueOf(3),
        BigInteger.valueOf(1),
        BigInteger.valueOf(4),
        BigInteger.valueOf(1),
        BigInteger.valueOf(5),
        BigInteger.valueOf(9)
    };

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
    /*@ public normal_behavior
      @ requires \static_invariant_for(BigInteger);
      @ requires currentIndex < VALUES.length;
      @ ensures currentIndex == \old(currentIndex) + 1;
      @ assignable currentIndex;
      @ determines \result.value \by currentIndex, (\seq_def int i; 0; VALUES.length; VALUES[i].value);
      @*/
    public static BigInteger uniformHash(final BigInteger upperBound, final String /*@nullable@*/ s1,
                                         final /*@nullable@*/ String s2, final /*@nullable@*/ String s3) {
        return VALUES[currentIndex++];
    }
}
