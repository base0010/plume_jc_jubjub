package com.base0010.plume;

import java.security.Key;

import javax.crypto.KeyAgreement;

import com.base0010.plume.BABYJUBJUB;
import com.base0010.plume.BN254;

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

	BN254 bn254;
	BABYJUBJUB bjj;
	Signature signature;

	// lens in bytes
	// confirm uncompressed pub len
	private static short PK_LEN = 65;
	private static short SK_LEN = 32;

	private static final byte TEST_HASH[] = {
		(byte) 0x00, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE, (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE,
		(byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE, (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE,
		(byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE, (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE,
		(byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE, (byte) 0xAB, (byte) 0xAD, (byte) 0xBA, (byte) 0xBE,
	};

	//intial hash byte 0x4f
	private static final byte H1[] = {
		(byte)0x00, (byte)0x70, (byte)0x89, (byte)0x8d, (byte)0x79, (byte)0xf4, (byte)0x74, (byte)0xd2,
		(byte)0x7c, (byte)0x97, (byte)0x2a, (byte)0xa1, (byte)0xa9, (byte)0xcc, (byte)0xb5, (byte)0x60,
		(byte)0x35, (byte)0xcb, (byte)0xcb, (byte)0x0f, (byte)0x46, (byte)0x2b, (byte)0x93, (byte)0xf7,
		(byte)0x8a, (byte)0xb8, (byte)0xca, (byte)0x7e, (byte)0x38, (byte)0xa1, (byte)0x37, (byte)0x2a
	};

	//intial hash byte 0x35
	private static final byte H2[] = {
		(byte)0x00, (byte)0x84, (byte)0x57, (byte)0x14, (byte)0x01, (byte)0x1c, (byte)0xba, (byte)0xaa,
		(byte)0x51, (byte)0xba, (byte)0x95, (byte)0x2f, (byte)0xd3, (byte)0xac, (byte)0xd3, (byte)0x47,
		(byte)0x25, (byte)0xab, (byte)0xaf, (byte)0xbd, (byte)0x7d, (byte)0x43, (byte)0xa9, (byte)0xde,
		(byte)0x27, (byte)0x9d, (byte)0xe4, (byte)0x63, (byte)0x23, (byte)0xad, (byte)0x1f, (byte)0x2e
	};

	//intial hash byte 0xbf
	private static final byte H3[] = {
		(byte)0x00, (byte)0x0a, (byte)0xda, (byte)0xf5, (byte)0x2e, (byte)0x75, (byte)0x12, (byte)0xa3,
		(byte)0x81, (byte)0x7e, (byte)0xab, (byte)0x90, (byte)0x37, (byte)0x91, (byte)0x13, (byte)0x16,
		(byte)0xdd, (byte)0xf7, (byte)0xd4, (byte)0xb0, (byte)0xfc, (byte)0x75, (byte)0xa0, (byte)0xfc,
		(byte)0x44, (byte)0x22, (byte)0x7a, (byte)0xb0, (byte)0x02, (byte)0x76, (byte)0x3e, (byte)0x09
	};

	private static final byte TEST_PRIVATE_KEY[] = {
		(byte)0x04, (byte)0x03, (byte)0x16, (byte)0x27, (byte)0x02, (byte)0x8b, (byte)0x95, (byte)0x19, (byte)0x6e, (byte)0x3b, (byte)0xfe, (byte)0x3b, (byte)0x73, (byte)0xc8, (byte)0x94, (byte)0xd8, (byte)0x14, (byte)0xda, (byte)0xde, (byte)0xdb, (byte)0x20, (byte)0xc6, (byte)0xd7, (byte)0xed, (byte)0x83, (byte)0xe2, (byte)0x74, (byte)0xc9, (byte)0x5e, (byte)0x00, (byte)0xbf, (byte)0xc3
	};
	static final byte BN254_PRIVKEY[] = {
			(byte) 0x24, (byte) 0xFA, (byte) 0x45, (byte) 0xE6, (byte) 0x1B, (byte) 0x72, (byte) 0x8E, (byte) 0x67,
			(byte) 0x28, (byte) 0x53, (byte) 0x83, (byte) 0x76, (byte) 0x85, (byte) 0x18, (byte) 0x9B, (byte) 0xF5,
			(byte) 0x61, (byte) 0x30, (byte) 0x11, (byte) 0x39, (byte) 0x98, (byte) 0x7D, (byte) 0xC5, (byte) 0x8A,
			(byte) 0xA9, (byte) 0x10, (byte) 0x32, (byte) 0x76, (byte) 0xD9, (byte) 0x52, (byte) 0xBE, (byte) 0xCC
	};
	static final byte BN254_PUBKEY[] = {
			(byte) 0x04, (byte) 0x13, (byte) 0x4F, (byte) 0x98, (byte) 0x09, (byte) 0x8B, (byte) 0x93, (byte) 0xF7,
			(byte) 0xF2, (byte) 0x76, (byte) 0x48, (byte) 0x5D, (byte) 0x2B, (byte) 0x11, (byte) 0xC8, (byte) 0x84,
			(byte) 0xAC, (byte) 0x4C, (byte) 0x4F, (byte) 0x2F, (byte) 0x2D, (byte) 0xA5, (byte) 0x22, (byte) 0x87,
			(byte) 0xD9, (byte) 0xC2, (byte) 0x7D, (byte) 0xD0, (byte) 0x58, (byte) 0xAF, (byte) 0x13, (byte) 0x41,
			(byte) 0xC5, (byte) 0x1A, (byte) 0x0F, (byte) 0xF9, (byte) 0xEB, (byte) 0x01, (byte) 0xD1, (byte) 0xB7,
			(byte) 0xE1, (byte) 0xFA, (byte) 0x4B, (byte) 0x0F, (byte) 0xD7, (byte) 0xF1, (byte) 0x17, (byte) 0xF8,
			(byte) 0xAD, (byte) 0x6C, (byte) 0x34, (byte) 0x4A, (byte) 0x7E, (byte) 0x26, (byte) 0x67, (byte) 0x53,
			(byte) 0xCD, (byte) 0xF6, (byte) 0x19, (byte) 0x15, (byte) 0x97, (byte) 0x28, (byte) 0xF6, (byte) 0x6F,
			(byte) 0x22
	};

	static final byte BN254_DIGEST[] = {
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
	};
	// SECP256k1 secp256k1 = new SECP256k1();
	// BABYJUBJUB babyjubjub = new BABYJUBJUB();

	// inits keypair with default TEST_HASH
	public PLUME() {
		bn254 = new BN254();
		bjj = new BABYJUBJUB();

		signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

		// keyPair = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);

		// sk = (ECPrivateKey) keyPair.getPrivate();

		// sk.setS(TEST_PRIVATE_KEY, (short) 0, (short) TEST_PRIVATE_KEY.length);

		// pk = (ECPublicKey) keyPair.getPublic();

	}

	// generates a random EC256 keypair
	public void handleGenerateNewKeypair() {
		// keyPair = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);

		// sk = (ECPrivateKey) keyPair.getPrivate();
		// pk = (ECPublicKey) keyPair.getPublic();
	}

	public static void install(byte bArray[], short bOffset, byte bLength) {
		PLUME Plume = new PLUME();
		Plume.register(bArray, (short) (bOffset + 1), (byte) bArray[bOffset]);
	}

	public void handleComputeTestNullifier(APDU apdu) {
		apdu.setIncomingAndReceive();

		byte[] buf = apdu.getBuffer();
		byte p1 = buf[2];
		byte p2 = buf[3];

		// todo: confirm these lengths, make global.
		short LEN_HASHED2CURVE = (short) TEST_HASH.length;
		// check length is equal to ecdsa sig len or 128?
		short LEN_NULLIFIER = (short) 128;

		byte[] hash2curveMsg = JCSystem.makeTransientByteArray(LEN_HASHED2CURVE, JCSystem.CLEAR_ON_DESELECT);

		nullifierOutput = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);

		KeyPair kp = new KeyPair(
				(ECPublicKey) KeyBuilder.buildKey(
						KeyBuilder.TYPE_EC_FP_PUBLIC, (short) 251, false),
				(ECPrivateKey) KeyBuilder.buildKey(
						KeyBuilder.TYPE_EC_FP_PRIVATE, (short) 251, false));
		ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();
		ECPublicKey pub = (ECPublicKey) kp.getPublic();

		BABYJUBJUB.setCurveParameters(priv);
		BABYJUBJUB.setCurveParameters(pub);

		priv.setS(TEST_PRIVATE_KEY, (short) 0, (short) TEST_PRIVATE_KEY.length);
		//pub.setW(BN254_PUBKEY, (short) 0, (short) BN254_PUBKEY.length);

		try {
			signature.init(priv, Signature.MODE_SIGN);
		} catch (CryptoException e) {
			Util.setShort(nullifierOutput, (short) 0, e.getReason());
		}

		short len;

		switch(p1){
			case (byte)0x00:
				len = signature.signPreComputedHash(TEST_HASH, (short) 0, (short) TEST_HASH.length, nullifierOutput, (short) 0);
			case (byte)0x01:
				len = signature.signPreComputedHash(H1, (short) 0, (short) H1.length, nullifierOutput, (short) 0);
			case (byte)0x02:
				len = signature.signPreComputedHash(H2, (short) 0, (short) H2.length, nullifierOutput, (short) 0);
			case (byte)0x03:
				len = signature.signPreComputedHash(H3, (short) 0, (short) H3.length, nullifierOutput, (short) 0);
			default:
				len = signature.signPreComputedHash(TEST_HASH, (short) 0, (short) TEST_HASH.length, nullifierOutput, (short) 0);

		}

		//priv.getS(nullifierOutput, (short)0);

		if (nullifierOutput != null) {
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) 128);
			apdu.sendBytesLong(nullifierOutput, (short) 0, (short) 128);
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
		// apdu.setIncomingAndReceive();

		// // todo: confirm these lengths, make global.
		// short LEN_HASHED2CURVE = (short) TEST_HASH.length;
		// short LEN_NULLIFIER = 128;

		// byte[] hash2curveMsg = JCSystem.makeTransientByteArray(LEN_HASHED2CURVE,
		// JCSystem.CLEAR_ON_DESELECT);
		// this.parseHash2Curve(apdu, hash2curveMsg);

		// byte[] nullifierOutput = JCSystem.makeTransientByteArray(LEN_NULLIFIER,
		// JCSystem.CLEAR_ON_DESELECT);

		// switch (this.selected_curve) {
		// case (byte) 0x0:
		// BABYJUBJUB.setCurveParameters(this.sk);
		// BABYJUBJUB.setCurveParameters(pk);

		// // ecPointMultiplier.init(this.sk);

		// // ecPointMultiplier.generateSecret(TEST_HASH, (short) 0, (short)
		// LEN_HASHED2CURVE, nullifierOutput,
		// // (short) 0);

		// case (byte) 0x01:
		// SECP256k1.setCurveParameters(this.sk);
		// SECP256k1.setCurveParameters(pk);

		// // ecPointMultiplier.init(this.sk);

		// // ecPointMultiplier.generateSecret(TEST_PRIVATE_KEY, (short) 0, (short)
		// LEN_HASHED2CURVE, nullifierOutput,
		// // (short) 0);

		// }

		// if (nullifierOutput != null) {
		// apdu.setOutgoing();
		// apdu.setOutgoingLength(LEN_NULLIFIER);
		// apdu.sendBytesLong(nullifierOutput, (short) 0, LEN_NULLIFIER);
		// }
	}

	// echo the current public key, use this to compare to off-card
	public void handleEchoPubkey(APDU apdu) {
		// byte[] pub = JCSystem.makeTransientByteArray((short) 65,
		// JCSystem.CLEAR_ON_DESELECT);
		// // public key exists
		// this.pk.getW(pub, PK_LEN);

		// if (pub != null) {
		// apdu.setOutgoing();
		// apdu.setOutgoingLength(PK_LEN);
		// apdu.sendBytesLong(pub, (short) 0, PK_LEN);
		// }
	}

	public void handleSetPrivateKey(APDU apdu) {

	}

	public void handleCurveSwitch(APDU apdu) {
		// byte[] buf = apdu.getBuffer();
		// switch (buf[ISO7816.OFFSET_INS]) {
		// case (byte) 0x00:
		// try {
		// this.selected_curve = (byte) 0x00;
		// } catch (ISOException e) {
		// ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		// }

		// case (byte) 0x01:
		// try {
		// this.selected_curve = (byte) 0x01;
		// } catch (ISOException e) {
		// ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		// }

		// }

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
				// try {
				// this.handleEchoPubkey(apdu);
				// } catch (ISOException e) {
				// ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				// }

				// bring your own hash outputs signature
			case (byte) 0x03:
				// try {

				// this.handleComputeAnyNullifier(apdu);

				// } catch (ISOException e) {
				// ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				// }
				// // bring your own private key
			case (byte) 0x04:
				// try {
				// // seed in a private key
				// this.handleSetPrivateKey(apdu);

				// } catch (ISOException e) {
				// ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				// }

				// switch out curve
				// default to BABYJUBJUB
				// P1 = 0 for BABYJUBJUB
				// P1 = 1 for SECP256K1
			case (byte) 0x05:
				// try {

				// this.handleCurveSwitch(apdu);
				// } catch (ISOException e) {
				// ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				// }

		}

	}

}
