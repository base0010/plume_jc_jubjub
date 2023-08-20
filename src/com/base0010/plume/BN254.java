package com.base0010.plume;

import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;

/**
 * Utility methods to work with the BN254 curve. As defined here 
 * https://neuromancer.sk/std/bn/bn254
 * 
 * 
 * This class is not meant to
 * be instantiated, but its init method
 * must be called during applet installation.
 */
public class BN254 {
    static final byte BN254_A[] = {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };
    static final byte BN254_B[] = {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x02
    };
    static final byte BN254_FP[] = {
            (byte) 0x25, (byte) 0x23, (byte) 0x64, (byte) 0x82, (byte) 0x40, (byte) 0x00, (byte) 0x00, (byte) 0x01,
            (byte) 0xBA, (byte) 0x34, (byte) 0x4D, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x08,
            (byte) 0x61, (byte) 0x21, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x13,
            (byte) 0xA7, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x13
    };
    static final byte BN254_G[] = {
            (byte) 0x04, (byte) 0x25, (byte) 0x23, (byte) 0x64, (byte) 0x82, (byte) 0x40, (byte) 0x00, (byte) 0x00,
            (byte) 0x01, (byte) 0xBA, (byte) 0x34, (byte) 0x4D, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x08, (byte) 0x61, (byte) 0x21, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x13, (byte) 0xA7, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x12, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x01
    };
    static final byte BN254_R[] = {
            (byte) 0x25, (byte) 0x23, (byte) 0x64, (byte) 0x82, (byte) 0x40, (byte) 0x00, (byte) 0x00, (byte) 0x01,
            (byte) 0xBA, (byte) 0x34, (byte) 0x4D, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x07,
            (byte) 0xFF, (byte) 0x9F, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x10,
            (byte) 0xA1, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x0D
    };

    static final byte BN254_K = (byte) 0x01;

    static final short BN254_KEY_SIZE = 256;

    private static final byte ALG_EC_SVDP_DH_PLAIN_XY = 6; // constant from JavaCard 3.0.5

    private KeyAgreement ecPointMultiplier;
    ECPrivateKey tmpECPrivateKey;

    /**
     * Allocates objects needed by this class. Must be invoked during the applet
     * installation exactly 1 time.
     */
    BN254() {
        // this.ecPointMultiplier = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
        // this.tmpECPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, BN254_KEY_SIZE,
        //         false);
        // setCurveParameters(tmpECPrivateKey);
    }

    /**
     * Sets the BN254 curve parameters to the given ECKey (public or private).
     *
     * @param key the key where the curve parameters must be set
     */
    static void setCurveParameters(ECKey key) {
        key.setFieldFP(BN254_FP, (short) 0x00, (short) BN254_FP.length);
        key.setA(BN254_A, (short) 0x00, (short) BN254_A.length);
        key.setB(BN254_B, (short) 0x00, (short) BN254_B.length);
        key.setG(BN254_G, (short) 0x00, (short) BN254_G.length);
        key.setR(BN254_R, (short) 0x00, (short) BN254_R.length);
        key.setK(BN254_K);
    }

    /**
     * Derives the public key from the given private key and outputs it in the
     * pubOut buffer. This is done by multiplying
     * the private key by the G point of the curve.
     *
     * @param privateKey the private key
     * @param pubOut     the output buffer for the public key
     * @param pubOff     the offset in pubOut
     * @return the length of the public key
     */
    short derivePublicKey(ECPrivateKey privateKey, byte[] pubOut, short pubOff) {
        return multiplyPoint(privateKey, BN254_G, (short) 0, (short) BN254_G.length, pubOut, pubOff);
    }

    /**
     * Derives the public key from the given private key and outputs it in the
     * pubOut buffer. This is done by multiplying
     * the private key by the G point of the curve.
     *
     * @param privateKey the private key
     * @param pubOut     the output buffer for the public key
     * @param pubOff     the offset in pubOut
     * @return the length of the public key
     */
    short derivePublicKey(byte[] privateKey, short privOff, byte[] pubOut, short pubOff) {
        tmpECPrivateKey.setS(privateKey, privOff, (short) (BN254_KEY_SIZE / 8));
        return derivePublicKey(tmpECPrivateKey, pubOut, pubOff);
    }

    /**
     * Multiplies a scalar in the form of a private key by the given point.
     * Internally uses a special version of EC-DH
     * supported since JavaCard 3.0.5 which outputs both X and Y in their
     * uncompressed form.
     *
     * @param privateKey the scalar in a private key object
     * @param point      the point to multiply
     * @param pointOff   the offset of the point
     * @param pointLen   the length of the point
     * @param out        the output buffer
     * @param outOff     the offset in the output buffer
     * @return the length of the data written in the out buffer
     */
    short multiplyPoint(ECPrivateKey privateKey, byte[] point, short pointOff, short pointLen, byte[] out,
            short outOff) {
        ecPointMultiplier.init(privateKey);
        return ecPointMultiplier.generateSecret(point, pointOff, pointLen, out, outOff);
    }
}