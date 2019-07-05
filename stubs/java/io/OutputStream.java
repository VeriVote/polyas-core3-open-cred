package java.io;

/**
 * @generated
 */
public abstract class OutputStream extends java.lang.Object implements java.io.Closeable, java.io.Flushable {
   /**
    * @generated
    */
   /*@ public behavior
     @ requires true;
     @ ensures true;
     @ assignable \everything;
     @*/
   public void write(byte[] param0, int param1, int param2) throws java.io.IOException;

   /**
    * @generated
    */
   /*@ public behavior
     @ requires true;
     @ ensures true;
     @ assignable \everything;
     @*/
   public void close() throws java.io.IOException;
}