## This is a repository for implementing PLUME - "Verifiably Deterministic Signatures on ECDSA" JavaCard wallets.


### This repository focuses an exploration for creating code for JavaCard capable secure elements, especially over a different curve(s), for example, babyjubjub as this is the lionshare hardware wallet platfroms

[PLUME docs and github](https://github.com/zk-nullifier-sig/zk-nullifier-sig/)


### Requirements:

## Device Requiremente
- (card, contactless etc) running Javacard 3.0.5ish (possibly 3.0.4 if JCMathLib is implemented)
that has support for EC point multiplication.

**This will work on existing JC wallet implementations ex. Status Keycard, Kong, and Semaphore USIM.

An explination of this can be found [JCMathLib](https://github.com/OpenCryptoProject/JCMathLib)
As well as a list of some supported cards here [JCAlgTest](https://www.fi.muni.cz/~xsvenda/jcalgtest/table.html)

### Features:
Hardware:


- [] Creates test PLUME nullifier using test private and test hash key over babyjubjub curve
- [] Creates PLUME nullifier using arbitrary private key and hash (imported or generated on-card)

Python CLI Tool:

- [] Transfers output of hash2curve output to SE
- [] Proves the inputs
- [] Verifies nullifier
