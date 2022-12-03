{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Bitcoin.Taro.CommitmentSpec where

import Bitcoin.Taro.Asset (Asset (..))
import qualified Bitcoin.Taro.Asset as Asset
import qualified Bitcoin.Taro.AssetSpec as Asset
import Bitcoin.Taro.Commitment
import qualified Bitcoin.Taro.MSSMT as MSSMT
import Bitcoin.Taro.TestUtils
import Crypto.Hash
import Data.Either (isRight)
import qualified Data.List.NonEmpty as NonEmpty
import Hedgehog
import Test.Tasty

type TestTaroTree = MSSMT.MapMSSMT (Digest SHA256) AssetCommitmentLeaf

type TestAssetTree = MSSMT.MapMSSMT (Digest SHA256) Asset.Asset

test_mint :: TestTree
test_mint =
  testGroup
    "mint"
    [ testPropertyNamed' "normal with zero amount" $
        withTests 1 $
          property $
            do
              assetGenesis <- forAll genGenesis
              issuance <- genIssuance assetGenesis 0
              mint @TestAssetTree @TestTaroTree issuance
                === Left (AssetError Asset.ZeroEmissionForNormalAsset),
      testPropertyNamed' "normal with non-zero amount" $
        withTests 1 $
          property $
            do
              assetGenesis <- forAll genGenesis
              issuance <- genIssuance assetGenesis 10
              assert $ isRight $ mint @TestAssetTree @TestTaroTree issuance,
      testPropertyNamed' "collectible with non-single amount" $
        withTests 1 $
          property $
            do
              assetGenesis <- forAll genGenesisCollectible
              issuance <- genIssuance assetGenesis 2
              mint @TestAssetTree @TestTaroTree issuance
                === Left (AssetError Asset.NonSingleEmissionForCollectableAsset),
      testPropertyNamed' "collectible with single amount" $
        withTests 1 $
          property $
            do
              assetGenesis <- forAll genGenesisCollectible
              issuance <- genIssuance assetGenesis 1
              assert $ isRight $ mint @TestAssetTree @TestTaroTree issuance,
      testPropertyNamed' "invalid asset type" $
        withTests 1 $
          property $
            do
              assetGenesis <- forAll $ Asset.genGenesisOfType (Asset.AssetType 255)
              issuance <- genIssuance assetGenesis 1
              mint @TestAssetTree @TestTaroTree issuance
                === Left (AssetError Asset.UnsupportedAssetType)
    ]
  where
    genIssuance assetGenesis amount = do
      assetScriptKey <- forAll genPubKey
      return Asset.Issuance
        { assetGenesis,
          assetFamilyKey = Nothing,
          emissions =
            NonEmpty.singleton $
              Asset.Emission
                { assetScriptKey,
                  amount,
                  lockTime = 1337,
                  relativeLockTime = 6,
                  taroAttributes = mempty
                }
        }

test_commitAssets :: TestTree
test_commitAssets =
  testGroup
    "commitAssets"
    [ testPropertyNamed'
        "family key mismatch"
        $ withTests 1
        $ property
        $ do
          genesis <- forAll genGenesis
          genesis' <- forAll genGenesis
          familyKey <- forAll $ Just <$> genFamilyKey genesis
          familyKey' <- forAll $ Just <$> genFamilyKey genesis'
          asset <- forAll $ genAsset genesis familyKey
          asset' <- forAll $ genAsset genesis familyKey'
          fmap assetCommitmentLeaf (commitAssets @TestAssetTree (NonEmpty.fromList [asset, asset']))
            === Left (AssetFamilyKeyMismatch familyKey familyKey'),
      testPropertyNamed'
        "no family key asset id mismatch"
        $ withTests 1
        $ property
        $ do
          genesis <- forAll genGenesis
          genesis' <- forAll genGenesis
          asset <- forAll $ genAsset genesis Nothing
          asset' <- forAll $ genAsset genesis' Nothing
          fmap assetCommitmentLeaf (commitAssets @TestAssetTree (NonEmpty.fromList [asset, asset']))
            === Left (AssetGenesisMismatch genesis genesis'),
      testPropertyNamed'
        "same family key asset id mismatch"
        $ withTests 1
        $ property
        $ do
          genesis <- forAll genGenesis
          genesis' <- forAll genGenesis
          familyKey@(Just fk) <- forAll $ Just <$> genFamilyKey genesis
          asset <- forAll $ genAsset genesis familyKey
          asset' <- forAll $ genAsset genesis' familyKey
          fmap assetCommitmentLeaf (commitAssets @TestAssetTree (NonEmpty.fromList [asset, asset']))
            === Left (AssetGenesisNotMemberOfFamily genesis' fk),
      testPropertyNamed'
        "duplicate script key"
        $ withTests 1
        $ property
        $ do
          genesis <- forAll genGenesis
          familyKey <- forAll $ Just <$> genFamilyKey genesis
          asset'' <- forAll $ genAsset genesis familyKey
          asset'@Asset {assetScriptKey} <- forAll $ genAsset genesis familyKey
          let asset = asset'' {assetScriptKey}
          fmap assetCommitmentLeaf (commitAssets @TestAssetTree (NonEmpty.fromList [asset, asset']))
            === Left (AssetScriptKeyNotUnique (assetCommitmentKey asset)),
      testPropertyNamed'
        "valid normal asset commitment with family key"
        $ withTests 1
        $ property
        $ do
          genesis <- forAll genGenesis
          familyKey <- forAll $ Just <$> genFamilyKey genesis
          asset <- forAll $ genAsset genesis familyKey
          asset' <- forAll $ genAsset genesis familyKey
          assert $ isRight (commitAssets @TestAssetTree (NonEmpty.fromList [asset, asset'])),
      testPropertyNamed'
        "valid collectible asset commitment with family key"
        $ withTests 1
        $ property
        $ do
          genesis <- forAll genGenesisCollectible
          familyKey <- forAll $ Just <$> genFamilyKey genesis
          asset <- forAll $ genAsset genesis familyKey
          asset' <- forAll $ genAsset genesis familyKey
          assert $ isRight (commitAssets @TestAssetTree (NonEmpty.fromList [asset, asset'])),
      testPropertyNamed'
        "valid normal asset commitment without family key"
        $ withTests 1
        $ property
        $ do
          genesis <- forAll genGenesis
          asset <- forAll $ genAsset genesis Nothing
          asset' <- forAll $ genAsset genesis Nothing
          assert $ isRight (commitAssets @TestAssetTree (NonEmpty.fromList [asset, asset'])),
      testPropertyNamed'
        "valid collectible asset commitment without family key"
        $ withTests 1
        $ property
        $ do
          genesis <- forAll genGenesisCollectible
          asset <- forAll $ genAsset genesis Nothing
          asset' <- forAll $ genAsset genesis Nothing
          assert $ isRight (commitAssets @TestAssetTree (NonEmpty.fromList [asset, asset']))
    ]

genAsset :: Asset.Genesis -> Maybe Asset.FamilyKey -> Gen Asset
genAsset assetGenesis assetFamilyKey = do
  asset <- Asset.genAsset
  return $ (asset :: Asset) {Asset.assetGenesis, Asset.assetFamilyKey}

genGenesis :: Gen Asset.Genesis
genGenesis = Asset.genGenesisOfType Asset.NormalAsset

genGenesisCollectible :: Gen Asset.Genesis
genGenesisCollectible = Asset.genGenesisOfType Asset.CollectableAsset

genFamilyKey :: Asset.Genesis -> Gen Asset.FamilyKey
genFamilyKey = Asset.genFamilyKeyForGenesis
