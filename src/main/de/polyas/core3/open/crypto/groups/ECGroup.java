package  de.polyas.core3.open.crypto.groups;

import java.math.BigInteger;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

public class ECGroup implements CyclicGroup {

    final SecP256K1Curve curve = new SecP256K1Curve();
    private final ECNamedCurveParameterSpec group =
            ECNamedCurveTable.getParameterSpec("secp256k1");

    public BigInteger order() {
        return curve.getOrder();
    }

    public ECPoint generator() {
        return group.getG();
    }


    public ECPoint pow(ECPoint p, BigInteger exponent) {
        BigInteger exponentPos =
                (exponent.compareTo(BigInteger.ZERO) < 0) ?
                        exponent.mod(order()) : exponent;
        return p.multiply(exponentPos);
    }

    public byte[] asBytes(ECPoint p) {
        return p.getEncoded(true);
    }

    public byte[] elementToBytes(ECPoint e) {
        return asBytes(e);
    }
}
