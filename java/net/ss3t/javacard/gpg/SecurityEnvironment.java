package net.ss3t.javacard.gpg;

import javacard.framework.*;
import javacard.security.KeyPair;

/**
 * Created by castillo on 3/31/15.
 */
public class SecurityEnvironment extends Object {
  private final KeyPair signatureKey;
  private final KeyPair confidentialityKey;
  private final KeyPair authenticationKey;
  private final byte[] fingerprints;
  private final byte[] generationDates;
  private final byte[] signatureCounter;

  public SecurityEnvironment() {
    signatureKey = new KeyPair(KeyPair.ALG_RSA_CRT, (short) 2048);
    confidentialityKey = new KeyPair(KeyPair.ALG_RSA_CRT, (short) 2048);
    authenticationKey = new KeyPair(KeyPair.ALG_RSA_CRT, (short) 2048);
    fingerprints = new byte[(short) 60];
    generationDates = new byte[(short) 12];
    signatureCounter = new byte[(short) 3];
  }

  public void clear() {
    signatureKey.getPrivate().clearKey();
    signatureKey.getPublic().clearKey();
    confidentialityKey.getPrivate().clearKey();
    confidentialityKey.getPublic().clearKey();
    authenticationKey.getPrivate().clearKey();
    authenticationKey.getPublic().clearKey();
    Util.arrayFillNonAtomic(fingerprints, (short) 0, (short) fingerprints.length, (byte) 0);
    Util.arrayFillNonAtomic(generationDates, (short)0, (short)generationDates.length, (byte)0);
    Util.arrayFillNonAtomic(signatureCounter, (short)0, (short)signatureCounter.length, (byte)0);
  }

  public KeyPair getSignatureKey() {
    return signatureKey;
  }

  public KeyPair getConfidentialityKey() {
    return confidentialityKey;
  }

  public KeyPair getAuthenticationKey() {
    return authenticationKey;
  }

  public byte[] getFingerprints() {
    return fingerprints;
  }

  public byte[] getGenerationDates() {
    return generationDates;
  }

  public byte[] getSignatureCounter() {
    return signatureCounter;
  }

  public void setFingerprints(APDU apdu) {
    short tag = Util.getShort(apdu.getBuffer(), ISO7816.OFFSET_P1);
    Gpg.getSharedInstance().storeFixedLength(apdu, fingerprints, (short) (20 * (tag - 0xC7)), (short) 20);
  }

  public void setGenerationDates(APDU apdu) {
    short tag = Util.getShort(apdu.getBuffer(), ISO7816.OFFSET_P1);
    Gpg.getSharedInstance().storeFixedLength(apdu, generationDates, (short) (4 * (tag - 0xCE)), (short) 4);
  }

  // This must be called from within a JavaCard transaction
  public void resetSignatureCounter() {
    signatureCounter[0] = (byte) 0;
    signatureCounter[1] = (byte) 0;
    signatureCounter[2] = (byte) 0;
  }

  public void incrementSignatureCounter() {
    JCSystem.beginTransaction();
    if (signatureCounter[2] != (byte) 0xFF) {
      signatureCounter[2] = (byte) ((signatureCounter[2] & 0xFF) + 1);
    } else {
      signatureCounter[2] = 0;
      if (signatureCounter[1] != (byte) 0xFF) {
        signatureCounter[1] = (byte) ((signatureCounter[1] & 0xFF) + 1);
      } else if (signatureCounter[0] != (byte) 0xFF) {
        signatureCounter[1] = 0;
        signatureCounter[0] = (byte) ((signatureCounter[0] & 0xFF) + 1);
      } else {
        JCSystem.abortTransaction();
        ISOException.throwIt(ISO7816.SW_FILE_FULL);
      }
    }
    JCSystem.commitTransaction();
  }

  public KeyPair getKey(byte type) {
    switch (type) {
      case (byte) 0xB6:
        return signatureKey;
      case (byte) 0xB8:
        return confidentialityKey;
      case (byte) 0xA4:
        return authenticationKey;
    }
    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    return null;  // Make the compiler happy.
  }

}
