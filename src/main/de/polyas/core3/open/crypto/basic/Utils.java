package de.polyas.core3.open.crypto.basic;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class Utils {

    private Utils() {}

    /////////////////////////////////////////////////////////////////////////////////
    // Conversion hex <-> bytes

    /*@ public normal_behavior
      @ requires true;
      @ requires_free (\forall \bigint i; 0 <= i && i < bytes.length; \dl_inByte(bytes[i]));
      @ ensures \fresh(\result) && \typeof(\result) == \type(String);
      @ assignable \nothing;
      @ determines \result \by bytes.length \new_objects \result;
      @*/
    public static String bytesToHexString(byte[] bytes) {
        StringBuilder r = new StringBuilder(bytes.length * 2);

        /*@ loop_invariant r.str != null && \fresh(r.str) && \typeof(r.str) == \type(String);
          @ loop_invariant 0 <= i && i <= bytes.length;
          @ loop_invariant bytes != null;
          @ loop_invariant r != null;
          @ decreases bytes.length - i;
          @ assignable r.str;
          @ determines r.str, bytes[*] \by \itself;
          @*/
        for (int i = 0; i < bytes.length; ++i) {
            byte b = bytes[i];
            int x = 0;

            if (b < 0) {
                x = 256 + b;
            } else {
                x = b;
            }

            int first4Bits = ((x) / 16) % 16;
            int second4Bits = ((x) % 16);

            r.append(hexCharacters()[first4Bits]).append(hexCharacters()[second4Bits]);
        }

        return r.toString();
    }

    /*@ public normal_behavior
      @ requires true;
      @ ensures \result.length == 16;
      @ ensures (\forall \bigint i; 0 <= i && i < \result.length; \dl_inChar(\result[i]));
      @ ensures \fresh(\result) && \typeof(\result) == \type(char[]);
      @ assignable \nothing;
      @ determines \result \by \nothing \new_objects \result;
      @ determines \result[*] \by \nothing;
      @*/
    private static char[] hexCharacters() {
        return "0123456789ABCDEF".toCharArray();
    }

    /*@ public normal_behavior
      @ ensures \fresh(\result) && \typeof(\result) == \type(String);
      @ assignable \nothing;
      @ determines \result \by \nothing \new_objects \result;
      @ determines \dl_strContent(\result) \by b[*];
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
