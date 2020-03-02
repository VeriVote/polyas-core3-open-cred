package org.bouncycastle.openpgp;

public class PGPPublicKeyRingCollection extends java.lang.Object implements org.bouncycastle.util.Iterable {

   /*@ public normal_behavior
     @ assignable \nothing;
     @*/
   public PGPPublicKeyRingCollection(java.io.InputStream param0, org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator param1) throws java.io.IOException, org.bouncycastle.openpgp.PGPException;

   public java.util.Iterator getKeyRings();
}