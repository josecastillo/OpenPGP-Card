package net.ss3t.javacard.gpg;

import javacard.framework.*;
import javacard.security.KeyPair;

import java.util.Arrays;

/**
 * Created by castillo on 3/31/15.
 *
 * This class encapsulates cryptographic tasks in a security environment. By default, the environment
 * contains no keys or metadata; these are lazily instantiated when requested.
 */
public class SecurityEnvironment extends Object {
  private KeyPair signatureKey;
  private KeyPair confidentialityKey;
  private KeyPair authenticationKey;
  private byte[] fingerprints;
  private byte[] generationDates;
  private byte[] signatureCounter;

  private final static byte[] defaultFingerprints = {
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };

  private final static byte[] defaultGenerationDates = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  private final static byte[] defaultSignatureCounter = {0, 0, 0};

  public void clear() {
    if (signatureKey != null) {
      signatureKey.getPrivate().clearKey();
      signatureKey.getPublic().clearKey();
      Util.arrayFillNonAtomic(signatureCounter, (short) 0, (short) signatureCounter.length, (byte) 0);
    }
    if (confidentialityKey != null) {
      confidentialityKey.getPrivate().clearKey();
      confidentialityKey.getPublic().clearKey();
    }
    if (authenticationKey != null) {
      authenticationKey.getPrivate().clearKey();
      authenticationKey.getPublic().clearKey();
    }
    if (fingerprints != null) {
      Util.arrayFillNonAtomic(fingerprints, (short) 0, (short) fingerprints.length, (byte) 0);
      Util.arrayFillNonAtomic(generationDates, (short) 0, (short) generationDates.length, (byte) 0);
    }
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
    if (fingerprints == null)
      return defaultFingerprints;
    return fingerprints;
  }

  public byte[] getGenerationDates() {
    if (generationDates == null)
      return defaultGenerationDates;
    return generationDates;
  }

  public byte[] getSignatureCounter() {
    if (signatureCounter == null)
      return defaultSignatureCounter;
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

  public KeyPair getOrInstantiateKey(byte type) {
    if (fingerprints == null) {
      JCSystem.beginTransaction();
      fingerprints = new byte[(short) 60];
      generationDates = new byte[(short) 12];
      JCSystem.commitTransaction();
    }
    switch (type) {
      case (byte) 0xB6:
        if (signatureKey == null) {
          JCSystem.beginTransaction();
          signatureKey = new KeyPair(KeyPair.ALG_RSA_CRT, (short) 2048);
          signatureCounter = new byte[(short) 3];
          JCSystem.commitTransaction();
        }
        return signatureKey;
      case (byte) 0xB8:
        if (confidentialityKey == null) {
          confidentialityKey = new KeyPair(KeyPair.ALG_RSA_CRT, (short) 2048);
        }
        return confidentialityKey;
      case (byte) 0xA4:
        if (authenticationKey == null) {
          authenticationKey = new KeyPair(KeyPair.ALG_RSA_CRT, (short) 2048);
        }
        return authenticationKey;
    }
    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    return null;  // Make the compiler happy.
  }

}
