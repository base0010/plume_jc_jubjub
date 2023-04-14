package com.base0010.plume;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class PLUME extends Applet {

    // both keypairs generic EC 256b
    private KeyPair keyPair;

    // secret key
    private ECPrivateKey sk;

    // public key
    private ECPublicKey pk;

    // message that's been hashed2curve
    private byte[] hashedMessage;

    // lens in bytes
    // confirm uncompressed pub len
    private static short PK_LEN = 65;
    private static short SK_LEN = 32;
    SECP256k1 secp256k1 = new SECP256k1();

    // init
    public PLUME() {
        // create keypair every run, this means we have to echo pk out, todo: import
        // keypair
        keyPair = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);

        sk = (ECPrivateKey) keyPair.getPrivate();
        pk = (ECPublicKey) keyPair.getPublic();

        // set these generic keys to SECP256k1 params
        SECP256k1.setCurveParameters(sk);
        SECP256k1.setCurveParameters(pk);

    }

    public static void install(byte bArray[], short bOffset, byte bLength) {
        PLUME Plume = new PLUME();
        Plume.register(bArray, (short) (bOffset + 1), (byte) bArray[bOffset]);
    }

    // @dev
    // res is the parsed out hash2curve ready to be multiplied by the sk
    public void parseHash2Curve(APDU apdu, byte[] res) {
        // todo: stub
        // return into res
    }

    public void handleComputeNullifier(APDU apdu) {
        apdu.setIncomingAndReceive();

        // todo: confirm these lengths, make global.
        short LEN_HASHED2CURVE = 128;
        short LEN_NULLIFIER = 128;

        byte[] hash2curveMsg = JCSystem.makeTransientByteArray(LEN_HASHED2CURVE, JCSystem.CLEAR_ON_DESELECT);
        this.parseHash2Curve(apdu, hash2curveMsg);

        byte[] nullifierOutput = JCSystem.makeTransientByteArray(LEN_NULLIFIER, JCSystem.CLEAR_ON_DESELECT);
        secp256k1.multiplyPoint(this.sk, hash2curveMsg, (short) 0, (short) LEN_HASHED2CURVE, nullifierOutput,
                (short) 0);

        if (nullifierOutput != null) {
            apdu.setOutgoing();
            apdu.setOutgoingLength(LEN_NULLIFIER);
            apdu.sendBytesLong(nullifierOutput, (short) 0, LEN_NULLIFIER);
        }
    }

    // echo the current public key, use this to compare to off-card
    public void handleEchoPubkey(APDU apdu) {
        byte[] pub = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);
        // public key exists
        this.pk.getW(pub, PK_LEN);

        if (pub != null) {
            apdu.setOutgoing();
            apdu.setOutgoingLength(PK_LEN);
            apdu.sendBytesLong(pub, (short) 0, PK_LEN);
        }
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            // return 9000 if it's just normal applet selection
            return;
        }

        byte buf[] = apdu.getBuffer();

        switch (buf[ISO7816.OFFSET_INS]) {
            // compute nullifier given hashed2curve input
            case (byte) 0x01:
                try {
                    this.handleComputeNullifier(apdu);
                } catch (ISOException e) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }

            case (byte) 0x02:
                try {
                    this.handleEchoPubkey(apdu);
                } catch (ISOException e) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }

        }

    }

}
