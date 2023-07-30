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

    private byte selected_curve = 0;

    // message that's been hashed2curve
    private byte[] hashedMessage;

    // lens in bytes
    // confirm uncompressed pub len
    private static short PK_LEN = 65;
    private static short SK_LEN = 32;

    private static final byte TEST_PRIVATE_KEY[] = {
            (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE, (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE,
            (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE, (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE,
            (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE, (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE,
            (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE, (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE,
    };

    private static final byte TEST_HASH[] = {
            (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE, (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE,
            (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE, (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE,
            (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE, (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE,
            (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE, (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE,
    };

    SECP256k1 secp256k1 = new SECP256k1();
    BABYJUBJUB babyjubjub = new BABYJUBJUB();

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

        switch (this.selected_curve) {
            case (byte) 0x0:
                babyjubjub.multiplyPoint(this.sk, hash2curveMsg, (short) 0, (short) LEN_HASHED2CURVE, nullifierOutput,
                        (short) 0);
            case (byte) 0x01:
                secp256k1.multiplyPoint(this.sk, hash2curveMsg, (short) 0, (short) LEN_HASHED2CURVE, nullifierOutput,
                        (short) 0);

        }

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

    public void handleSetPrivateKey(APDU apdu) {

    }

    public void handleSignHashToCurveInput(APDU apdu) {

    }

    public void handleCurveSwitch(APDU apdu) {
        switch (buf[ISO7816.OFFSET_INS]){
            case (byte) 0x00:
                try {
                    this.selected_curve = (byte)0x00;
                } catch (ISOException e) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }

            case (byte) 0x01:
                try {
                    this.selected_curve = (byte)0x01;
                } catch (ISOException e) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }


        }

    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            // return 9000 if it's just normal applet selection
            return;
        }

        byte buf[] = apdu.getBuffer();

        // compute nullifier
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

                // bring your own hash outputs signature
            case (byte) 0x03:
                try {

                    this.handleSignHashToCurveInput(apdu);

                } catch (ISOException e) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                // bring your own private key
            case (byte) 0x04:
                try {
                    // seed in a private key
                    this.handleSetPrivateKey(apdu);

                } catch (ISOException e) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }

                // switch out curve
                // default to BABYJUBJUB 
                // P1 = 0 for BABYJUBJUB
                // P1 = 1 for SECP256K1
            case (byte) 0x05:
                try {

                    this.handleCurveSwitch(apdu);
                } catch (ISOException e) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }

        }

    }

}
