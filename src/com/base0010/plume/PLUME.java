package com.base0010.plume;


import java.security.Key;

import javax.crypto.KeyAgreement;

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
    private byte[] nullifierOutput;

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

    // SECP256k1 secp256k1 = new SECP256k1();
    // BABYJUBJUB babyjubjub = new BABYJUBJUB();

    // inits keypair with default TEST_HASH
    public PLUME() {
        keyPair = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);

        sk = (ECPrivateKey) keyPair.getPrivate();

        sk.setS(TEST_PRIVATE_KEY, (short) 0, (short) TEST_PRIVATE_KEY.length);

        pk = (ECPublicKey) keyPair.getPublic();

    }

    // generates a random EC256 keypair
    public void handleGenerateNewKeypair() {
        keyPair = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);

        sk = (ECPrivateKey) keyPair.getPrivate();
        pk = (ECPublicKey) keyPair.getPublic();
    }

    public static void install(byte bArray[], short bOffset, byte bLength) {
        PLUME Plume = new PLUME();
        Plume.register(bArray, (short) (bOffset + 1), (byte) bArray[bOffset]);
    }

    public void handleComputeTestNullifier(APDU apdu) {
        apdu.setIncomingAndReceive();

        // todo: confirm these lengths, make global.
        short LEN_HASHED2CURVE = (short) TEST_HASH.length;
        // check length is equal to ecdsa sig len or 128?
        short LEN_NULLIFIER = (short) 128;

        byte[] hash2curveMsg = JCSystem.makeTransientByteArray(LEN_HASHED2CURVE, JCSystem.CLEAR_ON_DESELECT);

        nullifierOutput = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT);
        

        KeyPair kp = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);

        ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();
        ECPublicKey pub = (ECPublicKey) kp.getPublic();    


        //Set privkey Curve Params
        BABYJUBJUB.setCurveParameters(priv);

        //// todo: cant set BN254 parameters to publickey...
        // BABYJUBJUB.setCurveParameters(pub);

      
         try{

            //try to sign with the test hash.
            Signature sig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, true);
            
            kp.genKeyPair();
            priv.setS(TEST_PRIVATE_KEY, (short)0x00, (short)(256/8));

            sig.init(priv, Signature.MODE_SIGN); 

            sig.signPreComputedHash(TEST_HASH, (short)0, (short)TEST_HASH.length, nullifierOutput, (short)0);

         
         }catch(ISOException e){
             ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

         }


        if (nullifierOutput != null) {
            apdu.setOutgoing();
            apdu.setOutgoingLength((short)128);
            apdu.sendBytesLong(nullifierOutput, (short) 0, (short)128);
        }
        return;

    }

    // @dev
    // res is the parsed out hash2curve ready to be multiplied by the sk
    public void parseHash2Curve(APDU apdu, byte[] res) {
        // todo: stub
        // return into res
    }

    public void handleComputeAnyNullifier(APDU apdu) {
        apdu.setIncomingAndReceive();

        // todo: confirm these lengths, make global.
        short LEN_HASHED2CURVE = (short) TEST_HASH.length;
        short LEN_NULLIFIER = 128;

        byte[] hash2curveMsg = JCSystem.makeTransientByteArray(LEN_HASHED2CURVE, JCSystem.CLEAR_ON_DESELECT);
        this.parseHash2Curve(apdu, hash2curveMsg);

        byte[] nullifierOutput = JCSystem.makeTransientByteArray(LEN_NULLIFIER, JCSystem.CLEAR_ON_DESELECT);

        switch (this.selected_curve) {
            case (byte) 0x0:
                BABYJUBJUB.setCurveParameters(this.sk);
                BABYJUBJUB.setCurveParameters(pk);

                // ecPointMultiplier.init(this.sk);

                // ecPointMultiplier.generateSecret(TEST_HASH, (short) 0, (short) LEN_HASHED2CURVE, nullifierOutput,
                //         (short) 0);

            case (byte) 0x01:
                SECP256k1.setCurveParameters(this.sk);
                SECP256k1.setCurveParameters(pk);

                // ecPointMultiplier.init(this.sk);

                // ecPointMultiplier.generateSecret(TEST_PRIVATE_KEY, (short) 0, (short) LEN_HASHED2CURVE, nullifierOutput,
                //         (short) 0);

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

    public void handleCurveSwitch(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        switch (buf[ISO7816.OFFSET_INS]) {
            case (byte) 0x00:
                try {
                    this.selected_curve = (byte) 0x00;
                } catch (ISOException e) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }

            case (byte) 0x01:
                try {
                    this.selected_curve = (byte) 0x01;
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
            case (byte) 0x07:
                try {
                    this.handleComputeTestNullifier(apdu);
                    return;
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

                    this.handleComputeAnyNullifier(apdu);

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
