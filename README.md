# bitcoin-taro

> **Warning**: This library is highly experimental and should be used for education purposes with caution. For reference implementation, see: https://github.com/lightninglabs/taro.

Work in progress Haskell library implementing parts of the Taproot Asset 
Representation Overlay (Taro) protocol:

## [BIP-TARO](https://github.com/Roasbeef/bips/blob/bip-taro/bip-taro.mediawiki) - [Bitcoin.Taro.Asset](src/Bitcoin/Taro/Asset.hs)
- [X] Asset Tree Representation (Encoding ⇔ Decoding)
- [ ] Asset Creation
- [ ] Asset Burning
- [ ] Asset Transfers
- [ ] Asset Universes
- [ ] Multi-Hop Taro Asset Transfer

## [BIP-TARO-ADDR](https://github.com/Roasbeef/bips/blob/bip-taro/bip-taro-addr.mediawiki) - [Bitcoin.Taro.Address](src/Bitcoin/Taro/Address.hs)
- [X] Address Representation (Encoding ⇔ Decoding)
- [ ] Sending
- [ ] Spending

## [BIP-TARO-MS-SMT](https://github.com/Roasbeef/bips/blob/bip-taro/bip-taro-ms-smt.mediawiki) - [Bitcoin.Taro.MSSMT](src/Bitcoin/Taro/MSSMT.hs)
- [X] The Empty Hash Map
- [X] Lookup / Insert / Delete elements
- [X] Create / Verify Merkle Proofs
- [X] Compress / Decompress Merkle Proofs
- [ ] Caching Optimizations

## [BIP-TARO-PROOF-FILE](https://github.com/Roasbeef/bips/blob/bip-taro/bip-taro-proof-file.mediawiki) - [Bitcoin.Taro.ProofFile](src/Bitcoin/Taro/ProofFile.hs)
- [X] Proof File Representation (Encoding ⇔ Decoding)
- [ ] Proof File Verification

## [BIP-TARO-UNIVERSE](https://github.com/Roasbeef/bips/blob/bip-taro/bip-taro-universe.mediawiki)
- [ ] Asset Universes
- [ ] Asset Multiverses
- [ ] Pocket Universes

## [BIP-TARO-VM](https://github.com/Roasbeef/bips/blob/bip-taro/bip-taro-vm.mediawiki)
- [ ] Input Mapping
- [ ] Output Mapping
- [ ] State Transition Validation

## Differences from the BIPs

The spec is still being developed so the BIPs may be out of date with the 
[reference implementation](https://github.com/lightninglabs/taro). As library 
aims to track the behaviour of the reference implementation, here are some
notable differences and elaborations from the BIPs (I think) the library has 
come across and has tried to replicate here:

### BIP-TARO
* `asset_id` is explicitly, rather than implicitly, embedded in the Asset Leaf TLV: https://github.com/lightninglabs/taro/issues/62
* `asset_script_key` is just 32 bytes for the schnorr public key, rather than 33 bytes with the extra parity byte
* `genesis_outpoint.index` is in Big Endian, not in little endian as in the bitcoin wire format
* `previous_asset_witnesses` has length prefix in BigSize, rather than u16
* keys are encoding with their parity bytes: https://github.com/lightninglabs/taro/pull/187

### BIP-TARO-ADDR
* bech32m encoding relaxes the 90 character length limit defined in BIP-173
* `asset_id = 2` and is now explicitly embedded in the address TLV
* the TLV type `asset_type` is removed as it is now embedded in `asset_id`


### BIP-TARO-MS-SMT
* `compression_bits` of the `CompressedProof` is serialised in after compacting
 the bits into bytes.

### BIP-TARO-PROOF-FILE
* `asset_inclusion_proof.proof_version` is the 1 byte `asset_version`, not the 4 byte `proof_version`
* `taro_inclusion_proof.proof_version` is the 1 byte `asset_version`, not the 4 byte `proof_version`
* `taproot_exclusion_proof.bip86 = 2` 1 byte field added
* checksum of proof file is embedded in each proof, rather than a single value for the whole file
