{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

module Bitcoin.Taro.AssetSpec where

import Bitcoin
import Bitcoin.Taro.Asset
import qualified Bitcoin.Taro.MSSMT as MSSMT
import qualified Bitcoin.Taro.MSSMTSpec as MSSMT
import qualified Bitcoin.Taro.TLV as TLV
import Bitcoin.Taro.TestUtils
import Crypto.Hash (digestFromByteString)
import qualified Data.Binary as Bin
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Base16 as BSL16
import qualified Data.ByteString.Lazy.Char8 as BSL.Char8
import Data.Either (fromRight)
import Data.Foldable (toList)
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Maybe (fromJust)
import qualified Data.Set as Set
import Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Paths_bitcoin_taro (getDataFileName)
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.Hedgehog (testPropertyNamed)

test_Asset :: IO [TestTree]
test_Asset = do
    let split@Asset{assetGenesis = splitAssetGenesis, assetType = splitAssetType} =
            Asset
                { taroVersion = TaroVersion 1
                , assetGenesis =
                    Genesis
                        { genesisOutpoint =
                            OutPoint
                                { outPointHash = Bin.decode hashBytes1
                                , outPointIndex = 1
                                }
                        , assetTag = "asset"
                        , assetMeta = BSL.pack [1, 2, 3]
                        , outputIndex = 1
                        , assetType = CollectableAsset
                        }
                , assetType = CollectableAsset
                , amount = 1
                , lockTime = 1337
                , relativeLockTime = 6
                , previousAssetWitnesses =
                    [ AssetWitness
                        { previousAssetId =
                            Just
                                PreviousAssetId
                                    { previousOutpoint =
                                        OutPoint
                                            { outPointHash = Bin.decode hashBytes1
                                            , outPointIndex = 1
                                            }
                                    , assetId = AssetId $ fromJust $ digestFromByteString $ BSL.toStrict hashBytes1
                                    , assetScriptKey = Just pubKey
                                    }
                        , assetWitness = []
                        , splitCommitmentProof =
                            Just $
                                SplitCommitmentProof
                                    { proof = MSSMT.MerkleProof $ reverse $ toList (MSSMT.toCommitment <$> MSSMT.emptyBranches)
                                    , rootAsset = root
                                    }
                        }
                    ]
                , splitCommitmentRoot = Nothing
                , assetScriptVersion = AssetScriptVersion 1
                , assetScriptKey = pubKey
                , assetGroupKey =
                    Just
                        GroupKey
                            { key = pubKey
                            , signature = sig
                            }
                , taroAttributes = mempty
                }
        root =
            Asset
                { taroVersion = TaroVersion 1
                , assetGenesis = splitAssetGenesis
                , assetType = splitAssetType
                , amount = 1
                , lockTime = 1337
                , relativeLockTime = 6
                , previousAssetWitnesses =
                    [ AssetWitness
                        { previousAssetId =
                            Just
                                PreviousAssetId
                                    { previousOutpoint =
                                        OutPoint
                                            { outPointHash = Bin.decode hashBytes2
                                            , outPointIndex = 2
                                            }
                                    , assetId = AssetId $ fromJust $ digestFromByteString $ BSL.toStrict hashBytes2
                                    , assetScriptKey = Just pubKey
                                    }
                        , assetWitness = [BS.pack [2], BS.pack [2]]
                        , splitCommitmentProof = Nothing
                        }
                    ]
                , splitCommitmentRoot =
                    Just $
                        MSSMT.BranchCommitment $
                            MSSMT.Commitment
                                { commitDigest = fromJust $ digestFromByteString $ BSL.toStrict hashBytes1
                                , commitSum = 1337
                                }
                , assetScriptVersion = AssetScriptVersion 1
                , assetScriptKey = pubKey
                , assetGroupKey =
                    Just
                        GroupKey
                            { key = pubKey
                            , signature = sig
                            }
                , taroAttributes = mempty
                }
    rootEncodingFile <- getDataFileName "test/vectors/Asset.root.encoding.hex"
    rootEncoding <- fromRight "" . BSL16.decodeBase16 . head . BSL.Char8.lines <$> BSL.readFile rootEncodingFile
    splitEncodingFile <- getDataFileName "test/vectors/Asset.split.encoding.hex"
    splitEncoding <- fromRight "" . BSL16.decodeBase16 . head . BSL.Char8.lines <$> BSL.readFile splitEncodingFile
    pure
        [ testGroup
            "Encoding"
            [ testCase "root" $
                encodeHexLazy rootEncoding @=? encodeHexLazy (Bin.encode root)
            , testCase "split" $
                encodeHexLazy splitEncoding @=? encodeHexLazy (Bin.encode split)
            ]
        , testGroup
            "Decoding"
            [ testCase "root" $
                root @=? Bin.decode rootEncoding
            , testCase "split" $
                split @=? Bin.decode splitEncoding
            ]
        ]
  where
    hashBytes1 = BSL.pack $ replicate 32 1
    hashBytes2 = BSL.pack $ replicate 32 2
    pubKey = fromJust $ importPubKeyXY $ fromJust $ decodeHex "03a0afeb165f0ec36880b68e0baabd9ad9c62fd1a69aa998bc30e9a346202e078f"
    sig = fromJust $ importSignature $ fromJust $ decodeHex "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"

test_GroupKey_signVerify :: TestTree
test_GroupKey_signVerify =
    testPropertyNamed
        "forall (secKey, genesis) . genesis `isMemberOfGroup` groupKey secKey genesis"
        "prop_GroupKey_sign_verify_tautology"
        $ property
        $ do
            secKey <- forAll genSecKey
            genesis <- forAll genGenesis
            genesis `isMemberOfGroup` deriveGroupKey secKey genesis === True

test_Asset_encodeDecodeInverse :: TestTree
test_Asset_encodeDecodeInverse = encodeDecodeInverse genAsset

test_Genesis_encodeDecodeInverse :: TestTree
test_Genesis_encodeDecodeInverse = encodeDecodeInverse genGenesis

test_AssetWitness_encodeDecodeInverse :: TestTree
test_AssetWitness_encodeDecodeInverse = encodeDecodeInverse genAssetWitness

test_PreviousAssetId_encodeDecodeInverse :: TestTree
test_PreviousAssetId_encodeDecodeInverse = encodeDecodeInverse genPreviousAssetId

test_SplitCommitmentProof_encodeDecodeInverse :: TestTree
test_SplitCommitmentProof_encodeDecodeInverse = encodeDecodeInverse genSplitCommitmentProof

genAsset :: Gen Asset
genAsset =
    Asset
        <$> genTaroVersion
        <*> genGenesis
        <*> genAssetType
        <*> Gen.word64 Range.linearBounded
        <*> Gen.word64 Range.linearBounded
        <*> Gen.word64 Range.linearBounded
        <*> Gen.small genAssetWitnesses
        <*> Gen.maybe MSSMT.genRootNode
        <*> Gen.enumBounded
        <*> genPubKey
        <*> Gen.maybe genGroupKey
        <*> genUnknownAssetAttributes

genAssetOfType :: AssetType -> Gen Asset
genAssetOfType assetType = do
    asset <- genAsset
    return (asset :: Asset){assetType}

genTaroVersion :: Gen TaroVersion
genTaroVersion = Gen.enumBounded

genGenesis :: Gen Genesis
genGenesis =
    Genesis
        <$> genOutPoint
        <*> (BSL.fromStrict <$> Gen.bytes (Range.linear 0 256))
        <*> (BSL.fromStrict <$> Gen.bytes (Range.linear 0 256))
        <*> Gen.word32 Range.linearBounded
        <*> Gen.enumBounded

genGenesisOfType :: AssetType -> Gen Genesis
genGenesisOfType assetType = do
    genesis <- genGenesis
    return (genesis :: Genesis){assetType}

genAssetType :: Gen AssetType
genAssetType = Gen.enumBounded

genAssetWitnesses :: Gen [AssetWitness]
genAssetWitnesses = Gen.list (Range.linear 0 10) genAssetWitness

genAssetWitness :: Gen AssetWitness
genAssetWitness =
    Gen.filter canonical $
        AssetWitness
            <$> Gen.maybe genPreviousAssetId
            <*> genWitnessStack
            <*> Gen.maybe genSplitCommitmentProof
  where
    canonical = \case
        AssetWitness{previousAssetId = Nothing, splitCommitmentProof = Nothing} -> False
        AssetWitness{previousAssetId = Just{}, assetWitness = []} -> False
        _ -> True

genPreviousAssetId :: Gen PreviousAssetId
genPreviousAssetId =
    PreviousAssetId
        <$> genOutPoint
        <*> genAssetId
        <*> Gen.maybe genPubKey

genSplitCommitmentProof :: Gen SplitCommitmentProof
genSplitCommitmentProof =
    SplitCommitmentProof
        <$> MSSMT.genMerkleProof
        <*> Gen.small genAsset

genAssetId :: Gen AssetId
genAssetId = AssetId <$> genDigest

genGroupKey :: Gen GroupKey
genGroupKey =
    GroupKey
        <$> genPubKey
        <*> genSchnorrSig

genGroupKeyForGenesis :: Genesis -> Gen GroupKey
genGroupKeyForGenesis genesis = do
    secKey <- genSecKey
    pure $ deriveGroupKey secKey genesis

genAssetKeyGroup :: Gen AssetKeyGroup
genAssetKeyGroup = AssetKeyGroup <$> genPubKey

genUnknownAssetAttributes :: Gen (Map TLV.Type BSL.ByteString)
genUnknownAssetAttributes = Map.fromList <$> Gen.list (Range.linear 0 10) genUnknownField
  where
    genUnknownField = do
        typ <- Gen.filterT (`Set.notMember` knownAssetTypes) $ Gen.integral (Range.linear minBound maxBound)
        value <- BSL.fromStrict <$> Gen.bytes (Range.linear 1 256)
        pure (typ, value)

genSchnorrSig :: Gen Signature
genSchnorrSig = Gen.just $ importSignature <$> Gen.bytes (Range.singleton 64)
