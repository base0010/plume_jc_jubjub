package com.base0010.plume;

import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;

public class BABYJUBJUB {

    static final byte BABYJUBJUB_R[] = {
            (byte)0x06 ,(byte)0x0c ,(byte)0x89 ,(byte)0xce ,(byte)0x5c ,(byte)0x26 ,(byte)0x34 ,(byte)0x05 ,
            (byte)0x37 ,(byte)0x0a ,(byte)0x08 ,(byte)0xb6 ,(byte)0xd0 ,(byte)0x30 ,(byte)0x2b ,(byte)0x0b ,
            (byte)0xab ,(byte)0x3e ,(byte)0xed ,(byte)0xb8 ,(byte)0x39 ,(byte)0x20 ,(byte)0xee ,(byte)0x0a ,
            (byte)0x67 ,(byte)0x72 ,(byte)0x97 ,(byte)0xdc ,(byte)0x39 ,(byte)0x21 ,(byte)0x26 ,(byte)0xf1

    };

    static final byte BABYJUBJUB_FP[] = {
            (byte) 0x30, (byte) 0x64, (byte) 0x4e, (byte) 0x72, (byte) 0xe1, (byte) 0x31,
            (byte) 0xa0, (byte) 0x29, (byte) 0xb8, (byte) 0x50, (byte) 0x45, (byte) 0xb6, (byte) 0x81, (byte) 0x81,
            (byte) 0x58, (byte) 0x5d, (byte) 0x28, (byte) 0x33, (byte) 0xe8, (byte) 0x48, (byte) 0x79, (byte) 0xb9,
            (byte) 0x70, (byte) 0x91, (byte) 0x43, (byte) 0xe1, (byte) 0xf5, (byte) 0x93, (byte) 0xf0, (byte) 0x00,
            (byte) 0x00, (byte) 0x01
    };

    static final byte BABYJUBJUB_G[] = { (byte) 0x04, // format first byte
            // x-coordinate
            (byte)0x1f,(byte)0xde,(byte)0x0a,(byte)0x3c,(byte)0xac,(byte)0x7c,(byte)0xb4,(byte)0x6b,
            (byte)0x36,(byte)0xc7,(byte)0x9f,(byte)0x4c,(byte)0x0a,(byte)0x7a,(byte)0x73,(byte)0x2e,
            (byte)0x38,(byte)0xc2,(byte)0xc7,(byte)0xee,(byte)0x9a,(byte)0xc4,(byte)0x1f,(byte)0x44,
            (byte)0x39,(byte)0x2a,(byte)0x07,(byte)0xb7,(byte)0x48,(byte)0xa0,(byte)0x86,(byte)0x9f,

            (byte)0x20,(byte)0x3a,(byte)0x71,(byte)0x01,(byte)0x60,(byte)0x81,(byte)0x1d,(byte)0x5c,
            (byte)0x07,(byte)0xeb,(byte)0xae,(byte)0xb8,(byte)0xfe,(byte)0x1d,(byte)0x9c,(byte)0xe2,
            (byte)0x01,(byte)0xc6,(byte)0x6b,(byte)0x97,(byte)0x0d,(byte)0x66,(byte)0xf1,(byte)0x8d,
            (byte)0x0d,(byte)0x2b,(byte)0x26,(byte)0x4c,(byte)0x19,(byte)0x53,(byte)0x09,(byte)0xaa
    };
    static final byte BABYJUBJUB_A[] = { 
            (byte) 0x10, (byte) 0x21, (byte) 0x6f, (byte) 0x7b, (byte) 0xa0, (byte) 0x65,
            (byte) 0xe0, (byte) 0x0d, (byte) 0xe8, (byte) 0x1a, (byte) 0xc1, (byte) 0xe7, (byte) 0x80, (byte) 0x80,
            (byte) 0x72, (byte) 0xc9, (byte) 0xb8, (byte) 0x11, (byte) 0x4d, (byte) 0x6d, (byte) 0x7d, (byte) 0xe8,
            (byte) 0x7a, (byte) 0xdb, (byte) 0x16, (byte) 0xa0, (byte) 0xa7, (byte) 0x2f, (byte) 0x1a, (byte) 0x91,
            (byte) 0xf6, (byte) 0xa0 };
    static final byte BABYJUBJUB_B[] = { (byte) 0x23, (byte) 0xd8, (byte) 0x85, (byte) 0xf6, (byte) 0x47, (byte) 0xfe,
            (byte) 0xd5, (byte) 0x74, (byte) 0x3c, (byte) 0xad, (byte) 0x3d, (byte) 0x1e, (byte) 0xe4, (byte) 0xab,
            (byte) 0xa9, (byte) 0xc0, (byte) 0x43, (byte) 0xb4, (byte) 0xac, (byte) 0x0f, (byte) 0xc2, (byte) 0x76,
            (byte) 0x66, (byte) 0x58, (byte) 0xa4, (byte) 0x10, (byte) 0xef, (byte) 0xde, (byte) 0xb2, (byte) 0x1f,
            (byte) 0x70, (byte) 0x6e, };

    // correct cofactor?
    static final byte BABYJUBJUB_K = (byte) 0x01;

    static final short BABYJUBJUB_KEY_SIZE = 256;

    private KeyAgreement ecPointMultiplier;
    ECPrivateKey tmpECPrivateKey;

    BABYJUBJUB() {
        // this.ecPointMultiplier = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY,
        // false);
        // this.tmpECPrivateKey = (ECPrivateKey)
        // KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, BABYJUBJUB_KEY_SIZE,
        // false);
        // setCurveParameters(tmpECPrivateKey);
    }

    protected static void setCurveParameters(ECKey key) {
        key.setA(BABYJUBJUB_A, (short) 0x00, (short) BABYJUBJUB_A.length);
        key.setB(BABYJUBJUB_B, (short) 0x00, (short) BABYJUBJUB_B.length);
        key.setFieldFP(BABYJUBJUB_FP, (short) 0x00, (short) BABYJUBJUB_FP.length);
        key.setG(BABYJUBJUB_G, (short) 0x00, (short) BABYJUBJUB_G.length);
        key.setR(BABYJUBJUB_R, (short) 0x00, (short) BABYJUBJUB_R.length);
        key.setK(BABYJUBJUB_K);
    }

    // short multiplyPoint(ECPrivateKey privateKey, byte[] point, short pointOff,
    // short pointLen, byte[] out,
    // short outOff) {
    // ecPointMultiplier.init(privateKey);
    // return ecPointMultiplier.generateSecret(point, pointOff, pointLen, out,
    // outOff);
    // }
}