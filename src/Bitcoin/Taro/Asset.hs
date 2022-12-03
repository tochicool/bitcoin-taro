{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}

module Bitcoin.Taro.Asset where

import Bitcoin hiding (decode)
import qualified Bitcoin.Taro.MSSMT as MSSMT
import Bitcoin.Taro.TLV (TLV)
import qualified Bitcoin.Taro.TLV as TLV
import Bitcoin.Taro.Util
import Control.Applicative (optional, (<|>))
import Control.Monad (foldM, guard, replicateM, unless)
import Control.Monad.Except (MonadError, throwError)
import Crypto.Hash (Digest, HashAlgorithm (hashDigestSize), SHA256 (SHA256), hash, hashFinalize, hashInit, hashUpdate, hashUpdates)
import Data.Binary (Binary (get, put), Word64, decode, encode)
import Data.Binary.Get (getByteString, getLazyByteString)
import Data.Binary.Put (putByteString, putLazyByteString)
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Data.Foldable (toList, traverse_)
import Data.IntMap as IntMap (IntMap, lookup)
import Data.List (genericLength, sort)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NonEmpty
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Maybe (fromJust)
import qualified Data.Sequence as Seq
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Word (Word16, Word32, Word8)
import GHC.Generics (Generic)

-- | The leaf of an asset tree, serialised in Type-Length-Value (TLV) encoding.
data Asset = Asset
  { -- | The version of Taro being used, which allows a client to determine
    -- which other values of this record to expect.
    taroVersion :: TaroVersion,
    -- | The preimage of the identifier of the asset.
    assetGenesis :: Genesis,
    -- | The type of the asset.
    assetType :: AssetType,
    -- | The amount of the asset held in this leaf position.
    amount :: Word64,
    -- | The block time when an asset can be moved.
    lockTime :: Word64,
    -- | The block time when an asset can be moved, relative to the number of
    -- blocks after the mining transaction.
    relativeLockTime :: Word64,
    -- | The asset witnesses needed to verify the merging into the target asset
    -- leaf.
    previousAssetWitnesses :: [AssetWitness],
    -- | Used to commit to, and permit verification of, the new output split
    -- distribution for normal assets.
    splitCommitmentRoot :: Maybe (MSSMT.Node Asset),
    -- | The 2 byte asset script version that governs how the asset script key
    -- and the family script key is to be validated.
    assetScriptVersion :: AssetScriptVersion,
    -- | The external public key derived in a BIP 341 manner which may commit to
    -- an asset script that encumbers the asset leaf.
    assetScriptKey :: PubKeyXY,
    -- | The 32-byte public key as defined by BIP-340 followed by a 64-byte
    -- BIP 340 signature over the asset. This key can be used to associate
    -- distinct assets as identified by their Asset Ids. This is an optional
    -- field, and assets that don't contain this field are effectively
    -- considered to be a one-time only issuance event, meaning no further
    -- assets related to the derived 'assetId' can be created.
    assetFamilyKey :: Maybe FamilyKey,
    -- | Additional TLV fields with unknown semantics. This field can be used to
    -- commit to a set of arbitrary, and potentially mutable fields associated
    -- with an 'assetID'.
    taroAttributes :: Map TLV.Type BSL.ByteString
  }
  deriving (Generic, Show, Eq)
  deriving (Binary) via (TLV Asset)

instance TLV.ToStream Asset where
  toStream Asset {..} =
    mempty
      `TLV.addRecord` (taroVersion `TLV.ofType` taroVersionTLV)
      `TLV.addRecord` (assetGenesis `TLV.ofDynamicType` assetGenesisTLV)
      `TLV.addRecord` (assetType `TLV.ofType` assetTypeTLV)
      `TLV.addRecord` (TLV.BigSize amount `TLV.ofDynamicType` assetAmountTLV)
      `TLV.addRecords` case lockTime of
        0 -> Nothing
        _ -> Just $ TLV.BigSize lockTime `TLV.ofDynamicType` lockTimeTLV
      `TLV.addRecords` case relativeLockTime of
        0 -> Nothing
        _ -> Just $ TLV.BigSize relativeLockTime `TLV.ofDynamicType` relativeLockTimeTLV
      `TLV.addRecords` case previousAssetWitnesses of
        [] -> Nothing
        _ -> Just $ TLV.LengthPrefix @TLV.BigSize previousAssetWitnesses `TLV.ofDynamicType` previousAssetWitnessesTLV
      `TLV.addRecords` fmap (\root -> MSSMT.toCommitment root `TLV.ofType` splitCommitmentTLV) splitCommitmentRoot
      `TLV.addRecord` (assetScriptVersion `TLV.ofType` assetScriptVersionTLV)
      `TLV.addRecord` (ParityPubKey assetScriptKey `TLV.ofType` assetScriptKeyTLV)
      `TLV.addRecords` fmap (`TLV.ofType` assetFamilyKeyTLV) assetFamilyKey
      <> TLV.mapToStream taroAttributes

instance TLV.FromStream Asset where
  fromStream stream = do
    m <- TLV.streamToMap stream
    Asset
      <$> m
      `TLV.getValue` taroVersionTLV
      <*> m
      `TLV.getValue` assetGenesisTLV
      <*> m
      `TLV.getValue` assetTypeTLV
      <*> (TLV.unBigSize <$> m `TLV.getValue` assetAmountTLV)
      <*> (TLV.unBigSize <$> m `TLV.getValue` lockTimeTLV <|> pure 0)
      <*> (TLV.unBigSize <$> m `TLV.getValue` relativeLockTimeTLV <|> pure 0)
      <*> (TLV.unLengthPrefix @TLV.BigSize <$> m `TLV.getValue` previousAssetWitnessesTLV <|> pure [])
      <*> optional (MSSMT.BranchCommitment <$> (m `TLV.getValue` splitCommitmentTLV))
      <*> m
      `TLV.getValue` assetScriptVersionTLV
      <*> (unParityPubKey <$> m `TLV.getValue` assetScriptKeyTLV)
      <*> optional (m `TLV.getValue` assetFamilyKeyTLV)
      <*> pure (m `Map.withoutKeys` knownAssetTypes)

knownAssetTypes :: Set TLV.Type
knownAssetTypes =
  Set.fromAscList
    [ taroVersionTLV,
      assetGenesisTLV,
      assetTypeTLV,
      assetAmountTLV,
      lockTimeTLV,
      relativeLockTimeTLV,
      previousAssetWitnessesTLV,
      splitCommitmentTLV,
      assetScriptVersionTLV,
      assetScriptKeyTLV,
      assetFamilyKeyTLV
    ]

taroVersionTLV, assetGenesisTLV, assetTypeTLV, assetAmountTLV, lockTimeTLV, relativeLockTimeTLV, previousAssetWitnessesTLV, splitCommitmentTLV, assetScriptVersionTLV, assetScriptKeyTLV, assetFamilyKeyTLV :: TLV.Type
taroVersionTLV = 0
assetGenesisTLV = 1
assetTypeTLV = 2
assetAmountTLV = 3
lockTimeTLV = 4
relativeLockTimeTLV = 5
previousAssetWitnessesTLV = 6
splitCommitmentTLV = 7
assetScriptVersionTLV = 8
assetScriptKeyTLV = 9
assetFamilyKeyTLV = 10

newtype TaroVersion
  = TaroVersion Word8
  deriving (Generic, Show, Eq, Ord)
  deriving newtype (Enum, Bounded, Binary, TLV.StaticSize)

pattern TaroV0 :: TaroVersion
pattern TaroV0 = TaroVersion 0

data AssetId
  = AssetId (Digest SHA256)
  | RevealedGenesis Genesis
  | RevealedFamilyKey FamilyKey
  deriving (Generic, Show, Eq)

instance TLV.StaticSize AssetId where
  staticSize = fromIntegral $ hashDigestSize SHA256

instance Binary AssetId where
  put = putDigest . opaqueAssetId
  get = AssetId <$> getDigest

-- | The preimage of an 'AssetId'.
data Genesis = Genesis
  { -- | The first previous input outpoint used in the asset genesis transaction,
    -- serialized in Bitcoin wire format.
    genesisOutpoint :: OutPoint,
    -- | A random 32-byte value that represents a given asset, and can be used to
    -- link a series of discrete assets into a single asset family. In practice,
    -- this will typically be the hash of a human readable asset name.
    assetTag :: BSL.ByteString,
    -- | An opaque 32-byte value that can be used to commit to various metadata
    -- including external links, documents, stats, attributes, images, etc.
    -- Importantly, this field is considered to be immutable.
    assetMeta :: BSL.ByteString,
    -- | The index of the output which contains the unique Taro commitment in the
    -- genesis transaction.
    outputIndex :: Word32,
    -- | The type of the asset being minted.
    assetType :: AssetType
  }
  deriving (Generic, Show, Eq)

instance Binary Genesis where
  put Genesis {..} = do
    put $ TaroOutPoint genesisOutpoint
    put $ TLV.Bytes assetTag
    put $ TLV.Bytes assetMeta
    put outputIndex
    put assetType
  get =
    Genesis
      <$> (unTaroOutPoint <$> get)
      <*> (TLV.unBytes <$> get)
      <*> (TLV.unBytes <$> get)
      <*> get
      <*> get

instance HasAssetId Genesis where
  opaqueAssetId Genesis {genesisOutpoint, assetTag, assetMeta, outputIndex, assetType} =
    hashFinalize $
      hashUpdates
        hashInit
        $ BSL.toStrict
          <$> [ encode genesisOutpoint,
                assetTag,
                assetMeta,
                encode outputIndex,
                encode assetType
              ]
  toAssetId = RevealedGenesis

-- | An 'OutPoint' with the index decoded in Big-endian byte order.
newtype TaroOutPoint = TaroOutPoint
  { unTaroOutPoint :: OutPoint
  }
  deriving (TLV.StaticSize) via OutPoint

instance Binary TaroOutPoint where
  put (TaroOutPoint OutPoint {..}) = put outPointHash >> put outPointIndex
  get = TaroOutPoint <$> (OutPoint <$> get <*> get)

-- | The type of an asset.
newtype AssetType = AssetType Word8
  deriving (Generic, Show, Eq, Enum, Bounded)
  deriving (Binary, TLV.StaticSize) via Word8

-- | A normal asset.
pattern NormalAsset :: AssetType
pattern NormalAsset = AssetType 0

-- | A collectable asset.
pattern CollectableAsset :: AssetType
pattern CollectableAsset = AssetType 1

data AssetWitness = AssetWitness
  { -- | A reference to the previous input of an asset.
    previousAssetId :: Maybe PreviousAssetId,
    -- | A serialized witness in an identical format as Bitcoin's Segwit witness
    -- field. This field can only be blank if `previousAssetId` is blank.
    assetWitness :: WitnessStack,
    -- | Permits the spending of an asset leaf created as a result of an asset
    -- split.
    splitCommitmentProof :: Maybe SplitCommitmentProof
  }
  deriving (Generic, Show, Eq)
  deriving (Binary) via (TLV AssetWitness)

instance TLV.ToStream AssetWitness where
  toStream AssetWitness {..} =
    mempty
      `TLV.addRecords` fmap (`TLV.ofType` previousAssetIdTLV) previousAssetId
      `TLV.addRecords` ( case assetWitness of
                           [] -> Nothing
                           _ -> Just $ AssetWitnessStack assetWitness `TLV.ofDynamicType` assetWitnessTLV
                       )
      `TLV.addRecords` fmap
        (`TLV.ofDynamicType` splitCommitmentProofTLV)
        splitCommitmentProof

instance TLV.FromStream AssetWitness where
  fromStream :: TLV.Stream -> Maybe AssetWitness
  fromStream stream = do
    m <- TLV.streamToMap stream
    AssetWitness
      <$> optional (m `TLV.getValue` previousAssetIdTLV)
      <*> (unAssetWitnessStack <$> m `TLV.getValue` assetWitnessTLV <|> pure [])
      <*> optional (m `TLV.getValue` splitCommitmentProofTLV)

knownAssetWitnessTypes :: Set TLV.Type
knownAssetWitnessTypes =
  Set.fromAscList
    [ previousAssetIdTLV,
      assetWitnessTLV,
      splitCommitmentProofTLV
    ]

previousAssetIdTLV, assetWitnessTLV, splitCommitmentProofTLV :: TLV.Type
previousAssetIdTLV = 0
assetWitnessTLV = 1
splitCommitmentProofTLV = 2

-- | A 'WitnessStack' with a 'Binary' instance
newtype AssetWitnessStack = AssetWitnessStack
  { unAssetWitnessStack :: WitnessStack
  }

instance Binary AssetWitnessStack where
  put (AssetWitnessStack witnessStack) = do
    put $ VarInt $ genericLength witnessStack
    traverse_ putWitnessStackItem witnessStack
    where
      putWitnessStackItem bs = do
        put $ VarInt $ fromIntegral $ BS.length bs
        putByteString bs
  get =
    AssetWitnessStack <$> do
      VarInt i <- get
      replicateM (fromIntegral i) getWitnessStackItem
    where
      getWitnessStackItem = do
        VarInt i <- get
        getByteString (fromIntegral i)

-- | A reference to the previous input of an asset.
data PreviousAssetId = PreviousAssetId
  { previousOutpoint :: OutPoint,
    assetId :: AssetId,
    assetScriptKey :: Maybe PubKeyXY
  }
  deriving (Generic, Show, Eq)

instance Binary PreviousAssetId where
  put PreviousAssetId {..} = do
    put $ TaroOutPoint previousOutpoint
    put assetId
    case assetScriptKey of
      Nothing -> putLazyByteString $ BSL.pack $ replicate 33 0
      Just pubKey -> put $ ParityPubKey pubKey
  get =
    PreviousAssetId
      <$> (unTaroOutPoint <$> get)
      <*> get
      <*> ( Just . unParityPubKey <$> get <|> do
              keyBytes <- getLazyByteString 33
              guard $ keyBytes == BSL.pack (replicate 33 0)
              return Nothing
          )

instance TLV.StaticSize PreviousAssetId where
  staticSize = 101

-- | The asset witness for an asset split.
data SplitCommitmentProof = SplitCommitmentProof
  { -- | The merkle proof for a particular asset split resulting from a split
    -- commitment.
    proof :: MSSMT.MerkleProof Asset,
    -- | The asset containing the root of the split commitment tree from which the
    -- proof was computed from.
    rootAsset :: Asset
  }
  deriving (Generic, Show, Eq)

instance Binary SplitCommitmentProof where
  put SplitCommitmentProof {..} = do
    put $ TLV.VarBytes proof
    put $ TLV.VarBytes rootAsset
  get =
    SplitCommitmentProof
      <$> (TLV.unVarBytes <$> get)
      <*> (TLV.unVarBytes <$> get)

newtype AssetScriptVersion = AssetScriptVersion Word16
  deriving (Generic, Show, Eq)
  deriving newtype (Enum, Bounded, Binary, TLV.StaticSize)

pattern AssetScriptV0 :: AssetScriptVersion
pattern AssetScriptV0 = AssetScriptVersion 0

data FamilyKey = FamilyKey
  { key :: PubKeyXY,
    signature :: Signature
  }
  deriving (Generic, Show, Eq)

instance TLV.StaticSize FamilyKey where
  staticSize = 33 + 64

instance Binary FamilyKey where
  put FamilyKey {..} = do
    put $ ParityPubKey key
    putByteString $ exportSignatureCompact signature
  get =
    FamilyKey
      <$> (unParityPubKey <$> get)
      <*> do
        Just sig <- importSignature <$> getByteString 64
        return sig

instance HasAssetId FamilyKey where
  opaqueAssetId =
    hashFinalize
      . hashUpdate
        hashInit
      . BSL.toStrict
      . encode
  toAssetId = RevealedFamilyKey

newtype SchnorrSig = SchnorrSig BSL.ByteString
  deriving (Generic, Show, Eq)

instance Binary SchnorrSig where
  put (SchnorrSig sig) = putLazyByteString sig
  get = SchnorrSig <$> getLazyByteString 64

class HasAssetId a where
  opaqueAssetId :: a -> Digest SHA256
  toAssetId :: a -> AssetId
  toAssetId = AssetId . opaqueAssetId

instance HasAssetId AssetId where
  opaqueAssetId = \case
    AssetId assetId -> assetId
    RevealedGenesis genesis -> opaqueAssetId genesis
    RevealedFamilyKey familyKey -> opaqueAssetId familyKey

class HasAssetKeyFamily a where
  opaqueAssetKeyFamily :: a -> PubKeyXY
  toAssetKeyFamily :: a -> AssetKeyFamily
  toAssetKeyFamily = AssetKeyFamily . opaqueAssetKeyFamily

data AssetKeyFamily
  = AssetKeyFamily PubKeyXY
  | RevealedAssetKeyFamily AssetKeyFamilyPreimage
  deriving (Generic, Show, Eq)

instance TLV.StaticSize AssetKeyFamily where
  staticSize = TLV.staticSize @ParityPubKey

instance Binary AssetKeyFamily where
  put = put . ParityPubKey . opaqueAssetKeyFamily
  get = AssetKeyFamily . unParityPubKey <$> get

instance HasAssetKeyFamily AssetKeyFamily where
  opaqueAssetKeyFamily = \case
    AssetKeyFamily digest -> digest
    RevealedAssetKeyFamily keyFamily -> opaqueAssetKeyFamily keyFamily
  toAssetKeyFamily = id

data AssetKeyFamilyPreimage = AssetKeyFamilyPreimage
  { -- | A 32-byte public key.
    assetKeyInternal :: PubKeyXY,
    -- | The first previous input outpoint used in the asset genesis transaction
    -- , serialized in Bitcoin wire format.
    genesisOutpoint :: OutPoint,
    -- | The index of the output which contains the unique Taro commitment in
    -- the genesis transaction (4 byte, big-endian).
    outputIndex :: Word32,
    -- | The type of the asset being minted.
    assetType :: AssetType
  }
  deriving (Generic, Show, Eq)

instance HasAssetKeyFamily AssetKeyFamilyPreimage where
  opaqueAssetKeyFamily AssetKeyFamilyPreimage {..} =
    taprootOutputKey $
      TaprootOutput
        { taprootInternalKey = assetKeyInternal,
          taprootMAST =
            Just $
              MASTCommitment $
                hashFinalize $
                  hashUpdates
                    hashInit
                    [ exportPubKeyXY True assetKeyInternal,
                      BSL.toStrict $ encode outputIndex,
                      BSL.toStrict $ encode assetType
                    ]
        }
  toAssetKeyFamily = RevealedAssetKeyFamily

newtype AssetCommitment = AssetCommitment BSL.ByteString
  deriving (Generic, Show, Eq)
  deriving (Binary) via BSL.ByteString

data TaroTapReveal
  = LeafReveal
      { internalKey :: PubKeyXY,
        leafBytes :: ByteString
      }
  | BranchReveal
      { internalKey :: PubKeyXY,
        sibling1Bytes :: ByteString,
        sibling2Bytes :: ByteString
      }

taroMarkerPreimage :: ByteString
taroMarkerPreimage = "taro"

taroMarker :: Digest SHA256
taroMarker = hash taroMarkerPreimage

taroMarkerBS :: ByteString
taroMarkerBS = BA.convert taroMarker

isMemberOfFamily :: Genesis -> FamilyKey -> Bool
genesis `isMemberOfFamily` FamilyKey {key, signature} =
  schnorrVerify (fst $ xyToXO key) (BA.convert @(Digest SHA256) $ hash $ opaqueAssetId genesis) signature

deriveFamilyKey :: SecKey -> Genesis -> FamilyKey
deriveFamilyKey familySecretKey genesis =
  FamilyKey
    { key = derivePubKey familySecretKey,
      signature = fromJust $ schnorrSign (keyPairCreate familySecretKey) message
    }
  where
    message = BA.convert $ hash @_ @SHA256 $ opaqueAssetId genesis

-- | Validate the uniqueness of a Taro commitment in a TapScript tree
validTaroCommitment :: TxOut -> ScriptPathData -> Maybe TaroTapReveal -> ByteString -> Bool
validTaroCommitment commitmentOutput ScriptPathData {scriptPathInternalKey, scriptPathControl} maybeSiblingPreimage taroRoot
  | Just rootHash <- maybeRootHash,
    Right (PayWitness 0x01 actualOutputKey) <- decodeOutputBS (scriptOutput commitmentOutput),
    expectedOutputKey <- taprootOutputKey $ TaprootOutput {taprootInternalKey = scriptPathInternalKey, taprootMAST = Just $ MASTCommitment rootHash} =
    XOnlyPubKey expectedOutputKey == decode (BSL.fromStrict actualOutputKey)
  | otherwise = False
  where
    maybeRootHash = case scriptPathControl of
      [] -> Just $ hashLeaf taroRoot
      [siblingHash] | wellFormedTree siblingHash -> Just $ hashBranch taroRootHash siblingHash
      _ -> Nothing
    wellFormedTree siblingHash = case maybeSiblingPreimage of
      Nothing -> False
      Just siblingPreimage -> case siblingPreimage of
        LeafReveal {leafBytes} ->
          not (taroMarkerBS `BS.isPrefixOf` leafBytes) && BA.convert (hashLeaf taroRoot) == siblingHash
        BranchReveal {sibling1Bytes, sibling2Bytes} ->
          BA.convert (hashBranch sibling1Bytes sibling2Bytes) == siblingHash
    taroRootHash = BA.convert $ hashLeaf taroRoot

validNoTaroUpMySleeves :: Tx -> IntMap TaroTapReveal -> ByteString -> Bool
validNoTaroUpMySleeves Tx {txOut} tapReveals taroRoot =
  flip all (zip [0 ..] txOut) $ \(i, out) -> case extractOutputKey out of
    Nothing -> True
    Just actualOutputKey -> case IntMap.lookup i tapReveals of
      Nothing -> False
      Just LeafReveal {internalKey, leafBytes}
        | leafBytes == taroRoot -> False
        | leafHash <- hashLeaf leafBytes,
          expectedOutputKey <- taprootOutputKey $ TaprootOutput {taprootInternalKey = internalKey, taprootMAST = Just $ MASTCommitment leafHash} ->
          XOnlyPubKey expectedOutputKey == actualOutputKey
      Just BranchReveal {internalKey, sibling1Bytes, sibling2Bytes}
        | sibling1Bytes == taroRoot -> False
        | sibling2Bytes == taroRoot -> False
        | branchHash <- hashBranch sibling1Bytes sibling2Bytes,
          expectedOutputKey <- taprootOutputKey $ TaprootOutput {taprootInternalKey = internalKey, taprootMAST = Just $ MASTCommitment branchHash} ->
          XOnlyPubKey expectedOutputKey == actualOutputKey

extractOutputKey :: TxOut -> Maybe XOnlyPubKey
extractOutputKey txOut
  | Right (PayWitness 0x01 outputKey) <- decodeOutputBS (scriptOutput txOut) = Just $ decode (BSL.fromStrict outputKey)
  | otherwise = Nothing

hashLeaf :: ByteString -> Digest SHA256
hashLeaf = hashFinalize . hashUpdate (initTaggedHash "TapLeaf")

hashBranch :: (BA.ByteArrayAccess a, Ord a) => a -> a -> Digest SHA256
hashBranch l r = hashFinalize (initTaggedHash "TapBranch" `hashUpdates` sort [l, r])

-- | The issuance of an asset.
data Issuance = Issuance
  { -- | The genesis of the asset being issued across all the emissions.
    assetGenesis :: Genesis,
    -- | The family key of a multi-issuance asset. This is Nothing for a single
    -- issuance asset.
    assetFamilyKey :: Maybe FamilyKey,
    -- | The non-empty series of emissions of the asset in this batch.
    emissions :: NonEmpty Emission
  }
  deriving (Generic, Show, Eq)

-- | The properties that can be configured at each emission of an 'Asset' during
-- 'Issuance'.
data Emission = Emission
  { -- | The script key of the asset emission.
    assetScriptKey :: PubKeyXY,
    -- | The amount of the asset to emit. This is ignored for 'CollectableAsset'
    -- types.
    amount :: Word64,
    -- | The block time when an asset can be moved.
    lockTime :: Word64,
    -- | The block time when an asset can be moved, relative to the number of
    -- blocks after the mining transaction.
    relativeLockTime :: Word64,
    -- Additional immutable attributes for the asset emission.
    taroAttributes :: Map TLV.Type BSL.ByteString
  }
  deriving (Generic, Show, Eq)

data IssuanceError
  = UnsupportedAssetType
  | ZeroEmissionForNormalAsset
  | NonSingleEmissionForCollectableAsset
  deriving (Generic, Show, Eq)

-- | Issue a batch of assets for the given issuance if all emissions are valid,
-- otherwise fail.
mint :: MonadError IssuanceError m => Issuance -> m (NonEmpty Asset)
mint Issuance {..} =
  NonEmpty.fromList . toList
    <$> foldM
      ( \assets Emission {..} -> do
          let Genesis {assetType} = assetGenesis
          case assetType of
            NormalAsset ->
              unless (amount > 0) $
                throwError ZeroEmissionForNormalAsset
            CollectableAsset ->
              unless (amount == 1) $
                throwError NonSingleEmissionForCollectableAsset
            _ ->
              throwError UnsupportedAssetType
          return $
            assets
              Seq.|> Asset
                { taroVersion = TaroV0,
                  assetGenesis,
                  assetType,
                  amount,
                  assetScriptVersion = AssetScriptV0,
                  assetScriptKey,
                  lockTime,
                  relativeLockTime,
                  previousAssetWitnesses = mempty,
                  splitCommitmentRoot = Nothing,
                  assetFamilyKey,
                  taroAttributes
                }
      )
      mempty
      emissions

createNewAssetOutput :: Word64 -> Genesis -> PubKeyXY -> PubKeyXY -> TaprootOutput
createNewAssetOutput totalUnits genesis@Genesis {assetType} assetScriptKey outputInternalKey =
  let assetId = toAssetId genesis
      asset =
        Asset
          { taroVersion = TaroV0,
            assetGenesis = genesis,
            assetType,
            amount = totalUnits,
            assetScriptVersion = AssetScriptV0,
            assetScriptKey,
            lockTime = 0,
            relativeLockTime = 0,
            previousAssetWitnesses = mempty,
            splitCommitmentRoot = Nothing,
            assetFamilyKey = Nothing,
            taroAttributes = mempty
          }
      innerMsSmtDigest =
        MSSMT.digest . MSSMT.rootNode $ MSSMT.insert (BSL.toStrict $ encode $ XOnlyPubKey assetScriptKey) asset totalUnits MSSMT.emptyMapMSSMT
      outerMsSmtDigest =
        MSSMT.digest . MSSMT.rootNode $
          MSSMT.insert (BSL.toStrict $ encode assetId) (BA.convert innerMsSmtDigest :: ByteString) totalUnits MSSMT.emptyMapMSSMT
   in TaprootOutput
        { taprootInternalKey = outputInternalKey,
          taprootMAST = Just $ MASTCommitment outerMsSmtDigest
        }
