package de.polyas.core3.open.crypto.basic;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class Utils {

    private Utils() {}

    /////////////////////////////////////////////////////////////////////////////////
    // Conversion hex <-> bytes

    /*@ public normal_behavior
      @ assignable \nothing;
      @ determines \result \by bytes[*];
      @*/
    public static String bytesToHexString(byte[] bytes) {
        StringBuilder r = new StringBuilder(bytes.length * 2);

        /*@ loop_invariant r.string != null;
          @ decreases bytes.length - \index;
          @ assignable r.string;
          @*/
        for (byte b: bytes) {
            int first4Bits = ((b) / 16) % 16;
            int second4Bits = ((b) % 16);
            r.append(hexCharacters()[first4Bits]).append(hexCharacters()[second4Bits]);
        }

        return r.toString();
    }

    private static char[] hexCharacters() {
        return "0123456789ABCDEF".toCharArray();
    }

    /*@ public normal_behavior
      @ assignable \nothing;
      @ determines \result \by b[*];
      @*/
    public static String asHexString(byte[] b) {
        return bytesToHexString(b).toLowerCase();
    }


    /////////////////////////////////////////////////////////////////////////////////
    // Random big integer

    public static SecureRandom getInstanceStrong() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch(NoSuchAlgorithmException e) {
            return null;
        }
    }

    /////////////////////////////////////////////////////////////////////////////////
    // Message (byte array) builder

    public static class ByteArrayBuilderCtx {
        private int initialCapacity;

        private ByteBuffer buffer = ByteBuffer.allocate(initialCapacity);

        public ByteArrayBuilderCtx(final int initCapac) {
            initialCapacity = initCapac;
        }

        void putBytes(byte[] a) {
            ensureSpace(a.length);
            buffer.put(a);
        }

        void putInt(int n) {
            ensureSpace(4);
            buffer.putInt(n);
        }

        byte[] getBytes() {
            buffer.flip();
            int len = buffer.remaining();
            byte[] bs = new byte[len];
            System.arraycopy(buffer.array(), buffer.position(), bs, 0, len);
            return bs;
        }

        private void ensureSpace(int n) {
            if (buffer.remaining() < n) {
                reallocate(n);
            }
        }

        private void reallocate(int delta) {
            int currentLenght = buffer.position();
            int newSize = (currentLenght + delta) * 2;
            byte[] arr = new byte[newSize];
            buffer.flip(); // switch to the reading mode
            buffer.get(arr, 0, currentLenght); // reads everything from buf to arr
            buffer = ByteBuffer.wrap(arr);
            buffer.position(currentLenght);
        }
    }

    /**
     * Utility for creating byte arrays, by appending data of various types.
     *
     * @param maximalCapacity
     *      the maximal length of the produced byte array.
     *
     * @param s
     *      integer for builder block which appends data by calling putInt method.
     */
    public static byte[] buildByteArray(int maximalCapacity, final int s) {
        final ByteArrayBuilderCtx ctx = new ByteArrayBuilderCtx(maximalCapacity);
        ctx.putInt(s);
        return ctx.getBytes();
    }

}
