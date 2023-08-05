package com.base0010.plume;

import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;

public class BABYJUBJUB {
	// todo: r & fp mixed?
	static final byte BABYJUBJUB_R[] = {
			(byte) 0x25, (byte) 0x23, (byte) 0x64, (byte) 0x82, (byte) 0x40, (byte) 0x00, (byte) 0x00, (byte) 0x01,
			(byte) 0xBA, (byte) 0x34, (byte) 0x4D, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x07,
			(byte) 0xFF, (byte) 0x9F, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x10,
			(byte) 0xA1, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x0D,
	};

	static final byte BABYJUBJUB_FP[] = {
			(byte) 0x25, (byte) 0x23, (byte) 0x64, (byte) 0x82, (byte) 0x40, (byte) 0x00, (byte) 0x00, (byte) 0x01,
			(byte) 0xBA, (byte) 0x34, (byte) 0x4D, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x08,
			(byte) 0x61, (byte) 0x21, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x13,
			(byte) 0xA7, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x13,

	};

	static final byte BABYJUBJUB_G[] = { (byte) 0x04, // format first byte
			// x-coordinate
			(byte) 0x25, (byte) 0x23, (byte) 0x64, (byte) 0x82, (byte) 0x40, (byte) 0x00, (byte) 0x00, (byte) 0x01,
			(byte) 0xBA, (byte) 0x34, (byte) 0x4D, (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x08,
			(byte) 0x61, (byte) 0x21, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x13,
			(byte) 0xA7, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x12,
			// y-coordinate
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01 };

	static final byte BABYJUBJUB_A[] = {
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
	};
	static final byte BABYJUBJUB_B[] = {
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x02
	};

	// correct cofactor?
	static final byte BABYJUBJUB_K = (byte) 0x01;

	static final short BABYJUBJUB_KEY_SIZE = 256;

	private static final byte ALG_EC_SVDP_DH_PLAIN_XY = 6; // constant from JavaCard 3.0.5

	private KeyAgreement ecPointMultiplier;
	ECPrivateKey tmpECPrivateKey;

	BABYJUBJUB() {
		// this.ecPointMultiplier = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY,
		// false);
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