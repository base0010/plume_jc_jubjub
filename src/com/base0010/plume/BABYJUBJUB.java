package com.base0010.plume;

import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;

public class BABYJUBJUB {
	// todo: r & fp mixed?
	static final byte BABYJUBJUB_R[] = { (byte) 0x30, (byte) 0x64, (byte) 0x4e, (byte) 0x72, (byte) 0xe1, (byte) 0x31,
			(byte) 0xa0, (byte) 0x29, (byte) 0xb8, (byte) 0x50, (byte) 0x45, (byte) 0xb6, (byte) 0x81, (byte) 0x81,
			(byte) 0x58, (byte) 0x5d, (byte) 0x28, (byte) 0x33, (byte) 0xe8, (byte) 0x48, (byte) 0x79, (byte) 0xb9,
			(byte) 0x70, (byte) 0x91, (byte) 0x43, (byte) 0xe1, (byte) 0xf5, (byte) 0x93, (byte) 0xf0, (byte) 0x00,
			(byte) 0x00, (byte) 0x01

	};

	static final byte BABYJUBJUB_FP[] = { (byte) 0x30, (byte) 0x64, (byte) 0x4e, (byte) 0x72, (byte) 0xe1, (byte) 0x31,
			(byte) 0xa0, (byte) 0x29, (byte) 0xb8, (byte) 0x50, (byte) 0x45, (byte) 0xb6, (byte) 0x81, (byte) 0x81,
			(byte) 0x58, (byte) 0x5d, (byte) 0x59, (byte) 0xf7, (byte) 0x6d, (byte) 0xc1, (byte) 0xc9, (byte) 0x07,
			(byte) 0x70, (byte) 0x53, (byte) 0x3b, (byte) 0x94, (byte) 0xbe, (byte) 0xe1, (byte) 0xc9, (byte) 0x09,
			(byte) 0x37, (byte) 0x88 };

	static final byte BABYJUBJUB_G[] = { (byte) 0x04, // format first byte
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
	// double check A is also Gx
	static final byte BABYJUBJUB_A[] = { (byte) 0x10, (byte) 0x21, (byte) 0x6f, (byte) 0x7b, (byte) 0xa0, (byte) 0x65,
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
	static final byte BABYJUBJUB_K = (byte) 0x08;

	static final short BABYJUBJUB_KEY_SIZE = 256;

	private static final byte ALG_EC_SVDP_DH_PLAIN_XY = 6; // constant from JavaCard 3.0.5

	private KeyAgreement ecPointMultiplier;
	ECPrivateKey tmpECPrivateKey;

	BABYJUBJUB() {
//		this.ecPointMultiplier = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
		this.tmpECPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, BABYJUBJUB_KEY_SIZE,
				false);
		setCurveParameters(tmpECPrivateKey);
	}

	protected static void setCurveParameters(ECKey key) {
		key.setA(BABYJUBJUB_A, (short) 0x00, (short) BABYJUBJUB_A.length);
		key.setB(BABYJUBJUB_B, (short) 0x00, (short) BABYJUBJUB_B.length);
		key.setFieldFP(BABYJUBJUB_FP, (short) 0x00, (short) BABYJUBJUB_FP.length);
		key.setG(BABYJUBJUB_G, (short) 0x00, (short) BABYJUBJUB_G.length);
		key.setR(BABYJUBJUB_R, (short) 0x00, (short) BABYJUBJUB_R.length);
		key.setK(BABYJUBJUB_K);
	}

	short multiplyPoint(ECPrivateKey privateKey, byte[] point, short pointOff, short pointLen, byte[] out,
			short outOff) {
		ecPointMultiplier.init(privateKey);
		return ecPointMultiplier.generateSecret(point, pointOff, pointLen, out, outOff);
	}
}