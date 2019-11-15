package  de.polyas.core3.open.crypto.groups;

import java.math.BigInteger;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

public final class ECGroup implements CyclicGroup {

    public final SecP256K1Curve curve = new SecP256K1Curve();
    public final ECNamedCurveParameterSpec group =
            ECNamedCurveTable.getParameterSpec("secp256k1");

    //@ public instance invariant \invariant_for(curve) && \invariant_for(group);

    public BigInteger order() {
        return curve.getOrder();
    }

    public ECPoint generator() {
        return group.getG();
    }

    /*@ public normal_behavior
      @ requires \static_invariant_for(BigInteger);
      @ requires \invariant_for(p);
      @ requires \invariant_for(exponent);
      @ assignable \nothing;
      @ determines \result \by \nothing;
      @ determines \result.value \by p.value, exponent.value, curve.order;
      @*/
    public ECPoint pow(ECPoint p, BigInteger exponent) {
        BigInteger exponentPos =
                (exponent.compareTo(BigInteger.ZERO) < 0) ?
                        exponent.mod(order()) : exponent;
        return p.multiply(exponentPos);
    }

    /*@ public normal_behavior
      @ requires true;
      @ assignable \nothing;
      @ determines \result \by \nothing;
      @ determines \result[*] \by p.value;
      @*/
    public byte[] asBytes(ECPoint p) {
        return p.getEncoded(true);
    }

    /*@ public normal_behavior
      @ requires true;
      @ assignable \nothing;
      @ determines \result \by \nothing;
      @ determines \result[*] \by e.value;
      @*/
    public byte[] elementToBytes(ECPoint e) {
        return asBytes(e);
    }
}
