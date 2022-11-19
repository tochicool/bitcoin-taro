{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

module Bitcoin.Taro.ProofFileSpec where

import Bitcoin
import qualified Bitcoin.Taro.Asset as Asset
import qualified Bitcoin.Taro.AssetSpec as Asset
import qualified Bitcoin.Taro.MSSMTSpec as MSSMT
import Bitcoin.Taro.ProofFile
import Bitcoin.Taro.TestUtils
import Data.Binary (decode, encode)
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Base16 as BSL16
import qualified Data.ByteString.Lazy.Char8 as BSL.Char8
import Data.Either (fromRight)
import Data.Maybe (fromJust)
import Hedgehog (Gen)
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Paths_bitcoin_taro (getDataFileName)
import Test.Tasty
import Test.Tasty.HUnit

test_File_encodeDecodeInverse :: TestTree
test_File_encodeDecodeInverse =
  encodeDecodeInverseWith 25 genFile

test_HashedProof_encodeDecodeInverse :: TestTree
test_HashedProof_encodeDecodeInverse =
  encodeDecodeInverseWith 25 genHashedProof

test_Proof_encodeDecodeInverse :: TestTree
test_Proof_encodeDecodeInverse =
  encodeDecodeInverseWith 25 genProof

test_MerkleInclusionProof_encodeDecodeInverse :: TestTree
test_MerkleInclusionProof_encodeDecodeInverse =
  encodeDecodeInverse genMerkleInclusionProof

test_TaroTaprootProof_encodeDecodeInverse :: TestTree
test_TaroTaprootProof_encodeDecodeInverse =
  encodeDecodeInverse genTaroTaprootProof

test_AssetProof_encodeDecodeInverse :: TestTree
test_AssetProof_encodeDecodeInverse =
  encodeDecodeInverse genAssetProof

test_TaprootExclusionProof_encodeDecodeInverse :: TestTree
test_TaprootExclusionProof_encodeDecodeInverse =
  encodeDecodeInverse genTaprootExclusionProof

test_AssetInclusionProof_encodeDecodeInverse :: TestTree
test_AssetInclusionProof_encodeDecodeInverse =
  encodeDecodeInverse genAssetInclusionProof

test_TaroProof_encodeDecodeInverse :: TestTree
test_TaroProof_encodeDecodeInverse =
  encodeDecodeInverse genTaroProof

test_TapScriptPreimage_encodeDecodeInverse :: TestTree
test_TapScriptPreimage_encodeDecodeInverse =
  encodeDecodeInverse genTapScriptPreimage

test_Proof :: IO [TestTree]
test_Proof = do
  oddBlockEncodingFile <- getDataFileName "test/vectors/Block.odd.encoding.hex"
  Block {blockHeader, blockTxns} <- decode . fromRight "" . BSL16.decodeBase16 . head . BSL.Char8.lines <$> BSL.readFile oddBlockEncodingFile
  let proof =
        Proof
          { previousOutPoint = genesisOutpoint,
            blockHeader,
            anchorTransaction = head blockTxns,
            anchorTransactionMerkleProof = txMerkleProof,
            taroAssetLeaf = asset,
            taroProof =
              TaroTaprootProof
                { outputIndex = 1,
                  internalKey = pubKey,
                  taprootAssetProof =
                    Just
                      AssetProof
                        { taroProof,
                          taroAssetProof,
                          tapSiblingPreimage =
                            Just $
                              TapScriptPreimage
                                { siblingType = TapScriptLeaf,
                                  siblingPreimage = BSL.pack [1]
                                }
                        },
                  taroCommitmentExclusionProof = Nothing
                },
            taroExclusionProofs =
              [ TaroTaprootProof
                  { outputIndex = 2,
                    internalKey = pubKey,
                    taprootAssetProof =
                      Just
                        AssetProof
                          { taroProof,
                            taroAssetProof,
                            tapSiblingPreimage =
                              Just $
                                TapScriptPreimage
                                  { siblingType = TapScriptLeaf,
                                    siblingPreimage = BSL.pack [1]
                                  }
                          },
                    taroCommitmentExclusionProof = Nothing
                  },
                TaroTaprootProof
                  { outputIndex = 3,
                    internalKey = pubKey,
                    taprootAssetProof = Nothing,
                    taroCommitmentExclusionProof =
                      Just
                        TaprootExclusionProof
                          { tapPreimage1 =
                              Just $
                                TapScriptPreimage
                                  { siblingType = TapScriptBranch,
                                    siblingPreimage = BSL.pack [1]
                                  },
                            tapPreimage2 =
                              Just $
                                TapScriptPreimage
                                  { siblingType = TapScriptLeaf,
                                    siblingPreimage = BSL.pack [2]
                                  },
                            bip86 = True
                          }
                  },
                TaroTaprootProof
                  { outputIndex = 4,
                    internalKey = pubKey,
                    taprootAssetProof = Nothing,
                    taroCommitmentExclusionProof =
                      Just
                        TaprootExclusionProof
                          { tapPreimage1 = Nothing,
                            tapPreimage2 = Nothing,
                            bip86 = True
                          }
                  }
              ],
            splitRootProof =
              Just
                TaroTaprootProof
                  { outputIndex = 4,
                    internalKey = pubKey,
                    taprootAssetProof =
                      Just
                        AssetProof
                          { taroProof,
                            taroAssetProof,
                            tapSiblingPreimage = Nothing
                          },
                    taroCommitmentExclusionProof = Nothing
                  },
            taroInputSplits = []
          }
      proofWithSplits = proof {taroInputSplits = [split, split]}
      split = file ProofV0 [proof, proof]
  proofEncodingFile <- getDataFileName "test/vectors/Proof.encoding.hex"
  Right proofEncoding <- BSL16.decodeBase16 . head . BSL.Char8.lines <$> BSL.readFile proofEncodingFile
  proofSplitEncodingFile <- getDataFileName "test/vectors/Proof.split.encoding.hex"
  Right proofSplitEncoding <- BSL16.decodeBase16 . head . BSL.Char8.lines <$> BSL.readFile proofSplitEncodingFile
  pure
    [ testGroup
        "Encoding"
        [ testCase "proof" $
            encodeHexLazy proofEncoding @=? encodeHexLazy (encode proof),
          testCase "proof with splits" $
            encodeHexLazy proofSplitEncoding @=? encodeHexLazy (encode proofWithSplits)
        ],
      testGroup
        "Decoding"
        [ testCase "proof" $
            proof @=? decode proofEncoding,
          testCase "proof with splits" $
            proofWithSplits @=? decode proofSplitEncoding
        ]
    ]
  where
    pubKey = xOnlyPubKey $ decode $ fromJust $ decodeHexLazy "a0afeb165f0ec36880b68e0baabd9ad9c62fd1a69aa998bc30e9a346202e078f"
    txMerkleProof = decode $ fromJust $ decodeHexLazy "04076d0317ee70ee36cf396a9871ab3bf6f8e6d538d7f8a9062437dcb71c75fcf9522db339c186c1149843a4848990e6ddb9a6065f4bc1422af53f4bc86f1b084a89189ff0316cdc10511da71da757e553cada9f3b5b1434f3923673adb57d83caac392c38af156d6fc30b55fad4112df2b95531e68114e9ad10011e72f7b7cfdb0f"
    asset@Asset.Asset {assetGenesis = Asset.Genesis {genesisOutpoint}} = decode $ fromJust $ decodeHexLazy "000100016720906a2512941d98f5c3d979084a5664f2bd74ddb663a786a2b56fc214309975558a69e228303361376630353034376561643831353961623336373233346163636337366630383734373663351403a7f05047ead8159ab367234accc76f087476c5be745fc4010201010301010403fd0539050106066901670065000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008020000092102d55eb553989b45cb8a52292c6c4e8d1f5abb267c097172bf69675d850b88685c0a6102e0f719b0ef5979c047b42c1d20fac1b6a8a9aa9b4d1dd5af8ca2777f4e81eb14d11c292cb1e415536686f00424383f7d700de0e4ab4b0a972a95ddcd266b35058c84a63c5dbf62a4fc14080f47e8810f21cedfbf4b3cde95d769cec35668cd0f"
    taroProof = decode $ fromJust $ decodeHexLazy "00010001220000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    taroAssetProof = Just $ decode $ fromJust $ decodeHexLazy "00010001201ac000c58c1ce3aa048ea56210367a3cba00db3c3db339b87af37393a8aabb4102220000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

genFile :: Gen File
genFile =
  File
    <$> genProofVersion
    <*> Gen.list (Range.linear 0 2) (Gen.small genHashedProof)

genHashedProof :: Gen HashedProof
genHashedProof =
  HashedProof
    <$> genProof
    <*> genDigest

genProof :: Gen Proof
genProof =
  Proof
    <$> genOutPoint
    <*> genBlockHeader
    <*> genTx
    <*> genMerkleInclusionProof
    <*> Gen.small Asset.genAsset
    <*> genTaroTaprootProof
    <*> Gen.list (Range.linear 0 10) genTaroTaprootProof
    <*> Gen.maybe genTaroTaprootProof
    <*> Gen.list (Range.linear 0 2) (Gen.small genFile)

genMerkleInclusionProof :: Gen MerkleInclusionProof
genMerkleInclusionProof = do
  n <- Gen.word64 (Range.linear 0 10)
  MerkleInclusionProof n
    <$> Gen.list (Range.singleton $ fromIntegral n) genHash256
    <*> Gen.list (Range.singleton $ fromIntegral n) Gen.bool

genTaroTaprootProof :: Gen TaroTaprootProof
genTaroTaprootProof =
  TaroTaprootProof
    <$> Gen.word32 Range.linearBounded
    <*> genPubKey
    <*> Gen.maybe genAssetProof
    <*> Gen.maybe genTaprootExclusionProof

genAssetProof :: Gen AssetProof
genAssetProof =
  AssetProof
    <$> Gen.maybe genAssetInclusionProof
    <*> genTaroProof
    <*> Gen.maybe genTapScriptPreimage

genTaprootExclusionProof :: Gen TaprootExclusionProof
genTaprootExclusionProof =
  TaprootExclusionProof
    <$> Gen.maybe genTapScriptPreimage
    <*> Gen.maybe genTapScriptPreimage
    <*> Gen.bool

genAssetInclusionProof :: Gen AssetInclusionProof
genAssetInclusionProof =
  AssetInclusionProof
    <$> Asset.genTaroVersion
    <*> Asset.genAssetId
    <*> MSSMT.genCompressibleMerkleProof (Range.linear 0 10)

genTaroProof :: Gen TaroProof
genTaroProof =
  TaroProof
    <$> Asset.genTaroVersion
    <*> MSSMT.genCompressibleMerkleProof (Range.linear 0 10)

genProofVersion :: Gen ProofVersion
genProofVersion = Gen.enumBounded

genTapScriptPreimage :: Gen TapScriptPreimage
genTapScriptPreimage =
  TapScriptPreimage
    <$> genSiblingType
    <*> genLazyBytes (Range.linear 0 256)

genSiblingType :: Gen SiblingType
genSiblingType = Gen.enumBounded
