## This is a repository for implementing PLUME - "Verifiably Deterministic Signatures on ECDSA" on secure elements/ hardware wallets.


### This repository focuses an exploration for creating code for JavaCard capable secure elements, as this is the lionshare hardware wallet platfroms

[PLUME docs and github] https://github.com/zk-nullifier-sig/zk-nullifier-sig/


### Requirements:

Device (card, contactless etc) running Javacard 3.0.5ish (possibly 3.0.4 if JCMathLib is implemented)
that has support for EC point multiplication.

This will work on existing JC wallet implementations ex. Status Keycard, Kong, and Semaphore SIM.

An explination of this can be found [JCMathLib] https://github.com/OpenCryptoProject/JCMathLib
As well as a list of supported cards here [JCAlgTest] https://www.fi.muni.cz/~xsvenda/jcalgtest/table.html

### Features:
Hardware:

- [] Can create nullifier, given external hash2curve msg.
- [] Can do hash2curve algorithm on-device (SSWU).
- [] Can encode message to XMD
- [] Computes PLUME and other signals - pk, s, c , gPowR, hashMPKPowR


CLI:

- [] Transfers output of hash2curve output to SE
- [] Proves the inputs
- [] Verifies nullifier
