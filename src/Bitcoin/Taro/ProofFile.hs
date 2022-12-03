{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}

module Bitcoin.Taro.ProofFile where

import Bitcoin
import qualified Bitcoin.Taro.Asset as Asset
import qualified Bitcoin.Taro.MSSMT as MSSMT
import Bitcoin.Taro.TLV (TLV)
import qualified Bitcoin.Taro.TLV as TLV
import Bitcoin.Taro.Util (ParityPubKey (..), bytes, getDigest, putDigest, zeroDigest)
import Control.Applicative (optional, (<|>))
import Control.Monad (replicateM)
import Crypto.Hash (Digest, SHA256, hashFinalize, hashInit, hashUpdate)
import Data.Binary (Binary (get, put), encode)
import Data.Binary.Get (getRemainingLazyByteString)
import qualified Data.Binary.Get as Bin
import Data.Binary.Put (putLazyByteString)
import qualified Data.ByteString.Lazy as BSL
import Data.Foldable (traverse_)
import Data.List (genericLength)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Word (Word32, Word64, Word8)
import GHC.Generics (Generic)

-- | A proof file comprised of proofs for all of an asset's state transitions
-- back to the asset's genesis state.
data File = File
  { -- | The version of the proof file.
    fileVersion :: ProofVersion,
    -- | The proofs contained within the proof file starting from the genesis
    -- state, along with their checksums.
    proofs :: [HashedProof]
  }
  deriving (Generic, Show, Eq)

instance Binary File where
  put File {..} = do
    put fileVersion
    put @TLV.BigSize $ genericLength proofs
    put `traverse_` proofs
  get =
    File
      <$> get
      <*> do
        TLV.BigSize n <- get
        replicateM (fromIntegral n) get

-- | The empty proof file
emptyFile :: ProofVersion -> File
emptyFile = flip File mempty

-- | Constructs a new proof file given a version and a series of state
-- transition proofs.
file :: ProofVersion -> [Proof] -> File
file version = File version . hashProofs

data HashedProof = HashedProof
  { proof :: Proof,
    hash :: Digest SHA256
  }
  deriving (Generic, Show, Eq)

instance Binary HashedProof where
  put HashedProof {..} = do
    let proofBytes = encode proof
    put $ TLV.BigSize $ fromIntegral $ BSL.length proofBytes
    putLazyByteString proofBytes
    putDigest hash
  get =
    HashedProof
      <$> do
        TLV.BigSize n <- get
        Bin.isolate (fromIntegral n) get
      <*> getDigest

hashProofs :: [Proof] -> [HashedProof]
hashProofs = \case
  [] -> []
  (p : ps) ->
    scanl
      ( \HashedProof {hash = prevHash} proof ->
          HashedProof {proof, hash = hashProof prevHash proof}
      )
      HashedProof {proof = p, hash = hashProof zeroDigest p}
      ps

hashProof :: Digest SHA256 -> Proof -> Digest SHA256
hashProof prevHash proof =
  hashFinalize $
    hashInit
      `hashUpdate` prevHash
      `hashUpdate` BSL.toStrict (encode proof)

-- | A single inclusion or state transition proof.
data Proof = Proof
  { -- | The 36-byte outpoint of the Taro-committed output being spent. If this
    -- is the very first proof, then this value will be the "genesis outpoint"
    -- for the given asset.
    previousOutPoint :: OutPoint,
    -- | The 80-byte block header that includes a spend of the above outpoint.
    blockHeader :: BlockHeader,
    -- | The transaction spending the previous outpoint. This transaction
    -- commits to at least a single Taro asset tree within one of its outputs.
    anchorTransaction :: Tx,
    -- | The merkle proof of the anchor transaction.
    anchorTransactionMerkleProof :: MerkleInclusionProof,
    -- | Taro asset leaf that the proof is for.
    taroAssetLeaf :: Asset.Asset,
    -- | The 'TaprootProof' proving the new inclusion of the resulting asset
    -- within anchor transaction.
    taroProof :: TaroTaprootProof,
    -- | A series of exclusion proofs that prove that the other outputs in a
    -- transaction don't commit to a valid taro asset. This re-uses the
    -- 'TaroTaprootProof' type but will only contain exclusion proofs.
    taroExclusionProofs :: [TaroTaprootProof],
    -- | An optional 'TaprootProof' needed if this asset is the result of a
    -- split, to prove inclusion of the root asset of the split.
    splitRootProof :: Maybe TaroTaprootProof,
    -- | A nested full proof for any additional inputs found within the
    -- resulting asset.
    taroInputSplits :: [File]
  }
  deriving (Generic, Show, Eq)
  deriving (Binary) via (TLV Proof)

instance TLV.ToStream Proof where
  toStream Proof {..} =
    mempty
      `TLV.addRecord` (Asset.TaroOutPoint previousOutPoint `TLV.ofType` previousOutPointTLV)
      `TLV.addRecord` (blockHeader `TLV.ofType` blockHeaderTLV)
      `TLV.addRecord` (anchorTransaction `TLV.ofDynamicType` anchorTransactionTLV)
      `TLV.addRecord` (anchorTransactionMerkleProof `TLV.ofDynamicType` anchorTransactionMerkleProofTLV)
      `TLV.addRecord` (taroAssetLeaf `TLV.ofDynamicType` taroAssetLeafTLV)
      `TLV.addRecord` (taroProof `TLV.ofDynamicType` taroProofTLV)
      `TLV.addRecords` ( case taroExclusionProofs of
                           [] -> Nothing
                           _ -> Just $ TLV.LengthPrefix @TLV.BigSize taroExclusionProofs `TLV.ofDynamicType` taroExclusionProofsTLV
                       )
      `TLV.addRecords` fmap (`TLV.ofDynamicType` splitRootProofTLV) splitRootProof
      `TLV.addRecords` ( case taroInputSplits of
                           [] -> Nothing
                           _ -> Just $ TLV.LengthPrefix @TLV.BigSize taroInputSplits `TLV.ofDynamicType` taroInputSplitsTLV
                       )

instance TLV.FromStream Proof where
  fromStream tlv = do
    m <- TLV.streamToMap tlv
    Proof
      <$> (Asset.unTaroOutPoint <$> m `TLV.getValue` previousOutPointTLV)
      <*> (m `TLV.getValue` blockHeaderTLV)
      <*> (m `TLV.getValue` anchorTransactionTLV)
      <*> (m `TLV.getValue` anchorTransactionMerkleProofTLV)
      <*> (m `TLV.getValue` taroAssetLeafTLV)
      <*> (m `TLV.getValue` taroProofTLV)
      <*> (TLV.unLengthPrefix @TLV.BigSize <$> m `TLV.getValue` taroExclusionProofsTLV <|> pure [])
      <*> optional (m `TLV.getValue` splitRootProofTLV)
      <*> (TLV.unLengthPrefix @TLV.BigSize <$> m `TLV.getValue` taroInputSplitsTLV <|> pure [])

knownProofTypes :: Set TLV.Type
knownProofTypes =
  Set.fromAscList
    [ previousOutPointTLV,
      blockHeaderTLV,
      anchorTransactionTLV,
      anchorTransactionMerkleProofTLV,
      taroAssetLeafTLV,
      taroProofTLV,
      taroExclusionProofsTLV,
      taroInputSplitsTLV
    ]

previousOutPointTLV, blockHeaderTLV, anchorTransactionTLV, anchorTransactionMerkleProofTLV, taroAssetLeafTLV, taroProofTLV, taroExclusionProofsTLV, splitRootProofTLV, taroInputSplitsTLV :: TLV.Type
previousOutPointTLV = 0
blockHeaderTLV = 1
anchorTransactionTLV = 2
anchorTransactionMerkleProofTLV = 3
taroAssetLeafTLV = 4
taroProofTLV = 5
taroExclusionProofsTLV = 6
splitRootProofTLV = 7
taroInputSplitsTLV = 8

-- | The merkle inclusion proof of the anchor transaction, in a simplified
-- format to BIP-37 transaction merkle proofs.
data MerkleInclusionProof = MerkleInclusionProof
  { -- | The number of nodes in the proof.
    proofNodeCount :: Word64,
    -- | The double SHA256 hashes of length 'proofNodeCount' of the nodes in the
    -- partial merkle tree in reverse depth first order.
    proofNodes :: [Hash256],
    -- | A bit-field of length 'proofNodeCount' with a value of False indicating a
    -- left direction, and True indicating a right direction.
    proofDirectionBits :: [Bool]
  }
  deriving (Generic, Show, Eq)

instance Binary MerkleInclusionProof where
  put MerkleInclusionProof {..} = do
    put $ TLV.BigSize proofNodeCount
    put `traverse_` proofNodes
    put `traverse_` encodeMerkleFlags proofDirectionBits
  get = do
    n <- TLV.unBigSize <$> get
    let count = fromIntegral n
    MerkleInclusionProof n
      <$> replicateM count get
      <*> (take count . decodeMerkleFlags <$> replicateM ((count + bytes - 1) `div` bytes) get)

-- | A nested TLV that can be used to prove either inclusion of a taro asset, or
-- the lack of a taro commitment.
data TaroTaprootProof = TaroTaprootProof
  { -- | The index of the taproot output that the proof is for.
    outputIndex :: Word32,
    -- | The internal key of the taproot output at 'outputIndex'.
    internalKey :: PubKeyXY,
    -- | A commitment proof for an asset, proving the inclusion or exclusion of
    -- an asset within a Taro commitment.
    taprootAssetProof :: Maybe AssetProof,
    -- | A taproot control block proving that a taproot output is not committing
    -- to a Taro commitment. This field should be set only if the output does
    -- not contain a valid Taro commitment.
    taroCommitmentExclusionProof :: Maybe TaprootExclusionProof
  }
  deriving (Generic, Show, Eq)
  deriving (Binary) via (TLV TaroTaprootProof)

instance TLV.ToStream TaroTaprootProof where
  toStream TaroTaprootProof {..} =
    mempty
      `TLV.addRecord` (outputIndex `TLV.ofType` outputIndexTLV)
      `TLV.addRecord` (ParityPubKey internalKey `TLV.ofType` internalKeyTLV)
      `TLV.addRecords` fmap (`TLV.ofDynamicType` taprootAssetProofTLV) taprootAssetProof
      `TLV.addRecords` fmap (`TLV.ofDynamicType` taroCommitmentExclusionProofTLV) taroCommitmentExclusionProof

instance TLV.FromStream TaroTaprootProof where
  fromStream tlv = do
    m <- TLV.streamToMap tlv
    TaroTaprootProof
      <$> (m `TLV.getValue` outputIndexTLV)
      <*> (unParityPubKey <$> m `TLV.getValue` internalKeyTLV)
      <*> optional (m `TLV.getValue` taprootAssetProofTLV)
      <*> optional (m `TLV.getValue` taroCommitmentExclusionProofTLV)

knownTaroTaprootProofTypes :: Set TLV.Type
knownTaroTaprootProofTypes =
  Set.fromAscList
    [ outputIndexTLV,
      internalKeyTLV,
      taprootAssetProofTLV,
      taroCommitmentExclusionProofTLV
    ]

outputIndexTLV, internalKeyTLV, taprootAssetProofTLV, taroCommitmentExclusionProofTLV :: TLV.Type
outputIndexTLV = 0
internalKeyTLV = 1
taprootAssetProofTLV = 2
taroCommitmentExclusionProofTLV = 3

-- | A full commitment proof for an asset. It can either prove inclusion or
-- exclusion of an asset within a Taro commitment.
data AssetProof = AssetProof
  { -- | The proof that is used along with an asset leaf to arrive at the root
    -- of the inner asset commitment MS-SMT. This proof must be Nothing if the
    -- asset commitment for this particular asset is not found within the Taro
    -- commitment. In this case, the TaroProof below would be a non-inclusion
    -- proof of the asset commitment.
    taroAssetProof :: Maybe AssetInclusionProof,
    -- | The proof used along with an asset commitment leaf to arrive at the
    -- root of the outer taro commitment MS-SMT.
    taroProof :: TaroProof,
    -- | An optional preimage of a tap node used to hash together with the Taro
    -- commitment leaf node to arrive at the tapscript root of the expected
    -- output.
    tapSiblingPreimage :: Maybe TapScriptPreimage
  }
  deriving (Generic, Show, Eq)
  deriving (Binary) via (TLV AssetProof)

instance TLV.ToStream AssetProof where
  toStream AssetProof {..} =
    mempty
      `TLV.addRecords` fmap (`TLV.ofDynamicType` taroAssetProofTLV) taroAssetProof
      `TLV.addRecord` (taroProof `TLV.ofDynamicType` assetProofTaroProofTLV)
      `TLV.addRecords` fmap (`TLV.ofDynamicType` tapSiblingPreImageTLV) tapSiblingPreimage

instance TLV.FromStream AssetProof where
  fromStream tlv = do
    m <- TLV.streamToMap tlv
    AssetProof
      <$> optional (m `TLV.getValue` taroAssetProofTLV)
      <*> m
      `TLV.getValue` assetProofTaroProofTLV
      <*> optional (m `TLV.getValue` tapSiblingPreImageTLV)

knownAssetProofTypes :: Set TLV.Type
knownAssetProofTypes =
  Set.fromAscList
    [ taroAssetProofTLV,
      assetProofTaroProofTLV,
      tapSiblingPreImageTLV
    ]

taroAssetProofTLV, assetProofTaroProofTLV, tapSiblingPreImageTLV :: TLV.Type
taroAssetProofTLV = 0
assetProofTaroProofTLV = 1
tapSiblingPreImageTLV = 2

-- | A proof that a Taproot output does not including a Taro commitment.
data TaprootExclusionProof = TaprootExclusionProof
  { -- | The preimage for a Taproot tree node at depth 0 or 1, if specified.
    tapPreimage1 :: Maybe TapScriptPreimage,
    -- | The pair preimage for 'tapPreimage1' at depth 1, if specified.
    tapPreimage2 :: Maybe TapScriptPreimage,
    -- | Indicates that this is a normal BIP-86 wallet output that does not
    -- commit to any script or Taro root.
    bip86 :: Bool
  }
  deriving (Generic, Show, Eq)
  deriving (Binary) via (TLV TaprootExclusionProof)

instance TLV.ToStream TaprootExclusionProof where
  toStream TaprootExclusionProof {..} =
    mempty
      `TLV.addRecords` fmap (`TLV.ofDynamicType` tapPreimage1TLV) tapPreimage1
      `TLV.addRecords` fmap (`TLV.ofDynamicType` tapPreimage2TLV) tapPreimage2
      `TLV.addRecord` (bip86 `TLV.ofType` bip86TLV)

instance TLV.FromStream TaprootExclusionProof where
  fromStream tlv = do
    m <- TLV.streamToMap tlv
    TaprootExclusionProof
      <$> optional (m `TLV.getValue` tapPreimage1TLV)
      <*> optional (m `TLV.getValue` tapPreimage2TLV)
      <*> (m `TLV.getValue` bip86TLV)

knownTaprootExclusionProofTypes :: Set TLV.Type
knownTaprootExclusionProofTypes =
  Set.fromAscList
    [ tapPreimage1TLV,
      tapPreimage2TLV,
      bip86TLV
    ]

tapPreimage1TLV, tapPreimage2TLV, bip86TLV :: TLV.Type
tapPreimage1TLV = 0
tapPreimage2TLV = 1
bip86TLV = 2

-- | The proof that is used along with an asset leaf to arrive at the root of
-- the inner asset commitment MS-SMT.
data AssetInclusionProof = AssetInclusionProof
  { -- | The maximum version of the assets committed.
    proofVersion :: Asset.TaroVersion,
    -- | The common identifier for all assets found within the asset commitment.
    -- This can either be an `Asset.AssetId` or `Asset.FamilyKey`.
    assetId :: Asset.AssetId,
    -- | The proof that is used along with an asset leaf to arrive at the root
    -- of the inner asset commitment MS-SMT.
    msMstInclusionProof :: MSSMT.MerkleProof Asset.Asset
  }
  deriving (Generic, Show, Eq)
  deriving (Binary) via (TLV AssetInclusionProof)

instance TLV.ToStream AssetInclusionProof where
  toStream AssetInclusionProof {..} =
    mempty
      `TLV.addRecord` (proofVersion `TLV.ofType` assetProofVersionTLV)
      `TLV.addRecord` (assetId `TLV.ofType` assetAssetIdTLV)
      `TLV.addRecord` (msMstInclusionProof `TLV.ofDynamicType` assetMsMstInclusionProofTLV)

instance TLV.FromStream AssetInclusionProof where
  fromStream tlv = do
    m <- TLV.streamToMap tlv
    AssetInclusionProof
      <$> m
      `TLV.getValue` assetProofVersionTLV
      <*> m
      `TLV.getValue` assetAssetIdTLV
      <*> m
      `TLV.getValue` assetMsMstInclusionProofTLV

knownAssetInclusionProofTypes :: Set TLV.Type
knownAssetInclusionProofTypes =
  Set.fromAscList
    [ assetProofVersionTLV,
      assetAssetIdTLV,
      assetMsMstInclusionProofTLV
    ]

assetProofVersionTLV, assetAssetIdTLV, assetMsMstInclusionProofTLV :: TLV.Type
assetProofVersionTLV = 0
assetAssetIdTLV = 1
assetMsMstInclusionProofTLV = 2

-- | The proof used along with an asset commitment leaf to arrive at the root of
-- the outer taro commitment MS-SMT.
data TaroProof = TaroProof
  { -- | The max version committed of the asset commitments included in the
    -- taro commitment that the proof is for.
    proofVersion :: Asset.TaroVersion,
    -- | The proof used along with an asset commitment leaf to arrive at the
    -- root of the outer taro commitment MS-SMT.
    msMstInclusionProof :: MSSMT.MerkleProof Asset.AssetCommitment
  }
  deriving (Generic, Show, Eq)
  deriving (Binary) via (TLV TaroProof)

instance TLV.ToStream TaroProof where
  toStream TaroProof {..} =
    mempty
      `TLV.addRecord` (proofVersion `TLV.ofType` taroProofVersionTLV)
      `TLV.addRecord` (msMstInclusionProof `TLV.ofDynamicType` taroMsMstInclusionProofTLV)

instance TLV.FromStream TaroProof where
  fromStream tlv = do
    m <- TLV.streamToMap tlv
    TaroProof
      <$> m
      `TLV.getValue` taroProofVersionTLV
      <*> m
      `TLV.getValue` taroMsMstInclusionProofTLV

knownTaroProofTypes :: Set TLV.Type
knownTaroProofTypes =
  Set.fromAscList
    [ taroProofVersionTLV,
      taroMsMstInclusionProofTLV
    ]

taroProofVersionTLV, taroMsMstInclusionProofTLV :: TLV.Type
taroProofVersionTLV = 0
taroMsMstInclusionProofTLV = 1

newtype ProofVersion = ProofVersion Word32
  deriving (Generic, Show, Eq)
  deriving (Enum, Bounded, TLV.StaticSize, Binary) via Word32

pattern ProofV0 :: ProofVersion
pattern ProofV0 = ProofVersion 0

-- | A tap script preimage bytestring wrapped with a self-describing byte that
-- identifies the type of the pre-image.
data TapScriptPreimage = TapScriptPreimage
  { -- | The type of the preimage.
    siblingType :: SiblingType,
    -- | The preimage bytestring
    siblingPreimage :: BSL.ByteString
  }
  deriving (Generic, Show, Eq)

-- | The type of a 'TapScriptPreimage'.
newtype SiblingType = SiblingType Word8
  deriving (Generic, Show, Eq)
  deriving (Enum, Bounded, TLV.StaticSize, Binary) via Word8

-- | A pre-image that is a 32-byte leaf script.
pattern TapScriptLeaf :: SiblingType
pattern TapScriptLeaf = SiblingType 0

-- | A pre-image that is a branch with two 32-byte child pre-images.
pattern TapScriptBranch :: SiblingType
pattern TapScriptBranch = SiblingType 1

instance Binary TapScriptPreimage where
  put TapScriptPreimage {..} = do
    put siblingType
    putLazyByteString siblingPreimage
  get = TapScriptPreimage <$> get <*> getRemainingLazyByteString
