package de.polyas.core3.open.crypto.groups;

import java.math.BigInteger;

public interface CyclicGroup<GroupElement> {

    /**
     * The order of the group
     */
    public BigInteger order();

    /**
     * A generator of the group.
     */
    public GroupElement generator();

    /**
     * Returns 'a' to the power of 'exponent', where a is an element of the group
     * and 'exponent' is an integer (typically in the range [0, order()))
     */
    public GroupElement pow(GroupElement e, BigInteger exponent);

    /**
     * Return a canonical byte representation of the given group element. Used,
     * in particular, for hashing and signing.
     */
    public byte[] elementToBytes(GroupElement e);
}
