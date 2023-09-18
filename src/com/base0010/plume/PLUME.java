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


	private byte INCREMENTAL_HASH[] = {
		(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		
	};


	private static final byte TEST_PRIVATE_KEY[] = {
		(byte)0x03, (byte)0x23, (byte)0xdb, (byte)0xbd, (byte)0xa9, (byte)0xa5, (byte)0xaf, (byte)0xf5,
		(byte)0x70, (byte)0xd9, (byte)0x74, (byte)0xd7, (byte)0x1c, (byte)0x88, (byte)0x33, (byte)0x4c,
		(byte)0xf9, (byte)0x9a, (byte)0xb9, (byte)0xc0, (byte)0x45, (byte)0x5e, (byte)0x1d, (byte)0x25,
		(byte)0x46, (byte)0xca, (byte)0x03, (byte)0xca, (byte)0x06, (byte)0x9e, (byte)0xb1, (byte)0xe0
};

	

	// SECP256k1 secp256k1 = new SECP256k1();
	// BABYJUBJUB babyjubjub = new BABYJUBJUB();

	// inits keypair with default TEST_HASH
	public PLUME() {
		bn254 = new BN254();
		bjj = new BABYJUBJUB();

		signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

		// INCREMENTAL_HASH = new byte[32];
	}

	// generates a random EC256 keypair
	public void handleGenerateNewKeypair() {
		// keyPair = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);

		// sk = (ECPrivateKey) keyPair.getPrivate();
		// pk = (ECPublicKey) keyPair.getPublic();
	}

	public void incrementHash(){
		byte castLastByte = INCREMENTAL_HASH[31];
		if(INCREMENTAL_HASH[30] != 0x00){
			//logic for nonce > 255
		}
		//increment the last byte in the hash buf
		//ready to hash
		castLastByte++;
		INCREMENTAL_HASH[31] = castLastByte;
		
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


		nullifierOutput = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);

		// KeyPair kp = new KeyPair(
		// 		(ECPublicKey) KeyBuilder.buildKey(
		// 				KeyBuilder.TYPE_EC_FP_PUBLIC, (short) 256, false),
		// 		(ECPrivateKey) KeyBuilder.buildKey(
		// 				KeyBuilder.TYPE_EC_FP_PRIVATE, (short) 256, false));

		KeyPair kp = new KeyPair(KeyPair.ALG_EC_FP, (short)256);

		ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();
		ECPublicKey pub = (ECPublicKey) kp.getPublic();

		BABYJUBJUB.setCurveParameters(priv);
		BABYJUBJUB.setCurveParameters(pub);

		kp.genKeyPair();

		priv.setS(TEST_PRIVATE_KEY, (short) 0, (short) TEST_PRIVATE_KEY.length);
		// //pub.setW(BN254_PUBKEY, (short) 0, (short) BN254_PUBKEY.length);

		try {
			signature.init(priv, Signature.MODE_SIGN);
		} catch (CryptoException e) {
			Util.setShort(nullifierOutput, (short) 0, e.getReason());
		}


		
		short len = signature.signPreComputedHash(INCREMENTAL_HASH, (short) 0, (short) INCREMENTAL_HASH.length, nullifierOutput, (short) 0);
		
		//our seperator between sig and hash
		nullifierOutput[(short)(len+1)] = (byte)0xff;
		nullifierOutput[(short)(len+2)] = (byte)0xff;
		nullifierOutput[(short)(len+3)] = (byte)0xff;

		//copy the hash that was signed
		Util.arrayCopy(INCREMENTAL_HASH, (short)0, nullifierOutput, (short)(len+4), (short)INCREMENTAL_HASH.length);
		incrementHash();

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
