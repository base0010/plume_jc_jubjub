package com.base0010.plume;

import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;

/**
 * Utility methods to work with the SECP256k1 curve. This class is not meant to
 * be instantiated, but its init method
 * must be called during applet installation.
 */
public class BABYJUBJUB {
    static final byte BABYJUBJUB_FP[] = {
        (byte) 0x30, (byte) 0x64, (byte) 0x4e, (byte) 0x72, (byte) 0xe1, (byte) 0x31, (byte) 0xa0, (byte) 0x29,
        (byte) 0xb8, (byte) 0x50, (byte) 0x45, (byte) 0xb6, (byte) 0x81, (byte) 0x81, (byte) 0x58, (byte) 0x5d,
        (byte) 0x28, (byte) 0x33, (byte) 0xe8, (byte) 0x48, (byte) 0x79, (byte) 0xb9, (byte) 0x70, (byte) 0x91,
        (byte) 0x43, (byte) 0xe1, (byte) 0xf5, (byte) 0x93, (byte) 0xf0, (byte) 0x00, (byte) 0x00, (byte) 0x01
    };
    static final byte BABYJUBJUB_A[] = {
        (byte) 0x10, (byte) 0x21, (byte) 0x6f, (byte) 0x7b, (byte) 0xa0, (byte) 0x65, (byte) 0xe0, (byte) 0x0d,
        (byte) 0xe8, (byte) 0x1a, (byte) 0xc1, (byte) 0xe7, (byte) 0x80, (byte) 0x80, (byte) 0x72, (byte) 0xc9,
        (byte) 0xb8, (byte) 0x11, (byte) 0x4d, (byte) 0x6d, (byte) 0x7d, (byte) 0xe8, (byte) 0x7a, (byte) 0xdb,
        (byte) 0x16, (byte) 0xa0, (byte) 0xa7, (byte) 0x2f, (byte) 0x1a, (byte) 0x91, (byte) 0xf6, (byte) 0xa0 };

    static final byte BABYJUBJUB_B[] = {
        (byte) 0x30, (byte) 0x64, (byte) 0x4e, (byte) 0x72, (byte) 0xe1, (byte) 0x31, (byte) 0xa0, (byte) 0x29,
        (byte) 0xb8, (byte) 0x50, (byte) 0x45, (byte) 0xb6, (byte) 0x81, (byte) 0x81, (byte) 0x58, (byte) 0x5d,
        (byte) 0x59, (byte) 0xf7, (byte) 0x6d, (byte) 0xc1, (byte) 0xc9, (byte) 0x07, (byte) 0x70, (byte) 0x53,
        (byte) 0x3b, (byte) 0x94, (byte) 0xbe, (byte) 0xe1, (byte) 0xc9, (byte) 0x09, (byte) 0x37, (byte) 0x88 
        };


    static final byte BABYJUBJUB_G[] = {
        (byte) 0x04, // format first byte
        // x-coordinate
        (byte) 0x10, (byte) 0x21, (byte) 0x6f, (byte) 0x7b, (byte) 0xa0, (byte) 0x65, (byte) 0xe0, (byte) 0x0d,
        (byte) 0xe8, (byte) 0x1a, (byte) 0xc1, (byte) 0xe7, (byte) 0x80, (byte) 0x80, (byte) 0x72, (byte) 0xc9,
        (byte) 0xb8, (byte) 0x11, (byte) 0x4d, (byte) 0x6d, (byte) 0x7d, (byte) 0xe8, (byte) 0x7a, (byte) 0xdb,
        (byte) 0x16, (byte) 0xa0, (byte) 0xa7, (byte) 0x31, (byte) 0x50, (byte) 0x00, (byte) 0xdb, (byte) 0xb0,
        // y-coordinate
        (byte) 0x09, (byte) 0x6a, (byte) 0x5a, (byte) 0xc0, (byte) 0x87, (byte) 0x96, (byte) 0x7a, (byte) 0xda,
        (byte) 0x39, (byte) 0x0c, (byte) 0x3b, (byte) 0x65, (byte) 0x71, (byte) 0x21, (byte) 0xa1, (byte) 0x72,
        (byte) 0xc9, (byte) 0x92, (byte) 0x1a, (byte) 0x00, (byte) 0x64, (byte) 0x1b, (byte) 0x2b, (byte) 0x0c,
        (byte) 0xcb, (byte) 0x45, (byte) 0xc0, (byte) 0xd0, (byte) 0x5c, (byte) 0xc6, (byte) 0xa7, (byte) 0x32 };

    static final byte BABYJUBJUB_R[] = {
        (byte) 0x30, (byte) 0x64, (byte) 0x4e, (byte) 0x72, (byte) 0xe1, (byte) 0x31, (byte) 0xa0, (byte) 0x29,
        (byte) 0xb8, (byte) 0x50, (byte) 0x45, (byte) 0xb6, (byte) 0x81, (byte) 0x81, (byte) 0x58, (byte) 0x5d,
        (byte) 0x59, (byte) 0xf7, (byte) 0x6d, (byte) 0xc1, (byte) 0xc9, (byte) 0x07, (byte) 0x70, (byte) 0x53,
        (byte) 0x3b, (byte) 0x94, (byte) 0xbe, (byte) 0xe1, (byte) 0xc9, (byte) 0x09, (byte) 0x37, (byte) 0x88 };

    static final byte BABYJUBJUB_K = (byte) 0x01;

    static final short BABYJUBJUB_KEY_SIZE = 256;

    private static final byte ALG_EC_SVDP_DH_PLAIN_XY = 6; // constant from JavaCard 3.0.5

    private KeyAgreement ecPointMultiplier;
    ECPrivateKey tmpECPrivateKey;

    /**
     * Allocates objects needed by this class. Must be invoked during the applet
     * installation exactly 1 time.
     */
    BABYJUBJUB() {
        this.ecPointMultiplier = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
        this.tmpECPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, BABYJUBJUB_KEY_SIZE,
                false);
        setCurveParameters(tmpECPrivateKey);
    }

    /**
     * Sets the BABYJUBJUB curve parameters to the given ECKey (public or private).
     *
     * @param key the key where the curve parameters must be set
     */
    static void setCurveParameters(ECKey key) {
        key.setA(BABYJUBJUB_A, (short) 0x00, (short) BABYJUBJUB_A.length);
        key.setB(BABYJUBJUB_B, (short) 0x00, (short) BABYJUBJUB_B.length);
        key.setFieldFP(BABYJUBJUB_FP, (short) 0x00, (short) BABYJUBJUB_FP.length);
        key.setG(BABYJUBJUB_G, (short) 0x00, (short) BABYJUBJUB_G.length);
        key.setR(BABYJUBJUB_R, (short) 0x00, (short) BABYJUBJUB_R.length);
        key.setK(BABYJUBJUB_K);
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
        return multiplyPoint(privateKey, BABYJUBJUB_G, (short) 0, (short) BABYJUBJUB_G.length, pubOut, pubOff);
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
        tmpECPrivateKey.setS(privateKey, privOff, (short) (BABYJUBJUB_KEY_SIZE / 8));
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