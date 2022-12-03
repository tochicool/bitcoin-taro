{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Bitcoin.Taro.Commitment where

import Bitcoin hiding ((:|))
import qualified Bitcoin.Taro.Asset as Asset
import qualified Bitcoin.Taro.MSSMT as MSSMT
import Bitcoin.Taro.Util
import Control.Monad.Except
import Crypto.Hash (Digest, SHA256, hash, hashFinalize, hashInit, hashUpdate, hashUpdates)
import Data.Binary (Binary (get, put), encode)
import Data.ByteArray.Mapping (fromW64BE)
import Data.ByteString
import qualified Data.ByteString.Lazy as BSL
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.Word (Word64)
import GHC.Generics (Generic)

data IssuanceError
    = AssetError Asset.IssuanceError
    | CommitmentError AssetError
    deriving (Generic, Show, Eq)

{- | Issue a batch of assets for the given issuance within a new Taro
 commitment if all assets within the asset commitment are valid, otherwise
 fail.
-}
mint :: forall assetTree taroTree m. (AssetTreeWriter assetTree (ExceptT AssetError m), TaroTreeWriter taroTree m, MonadError IssuanceError m) => Asset.Issuance -> m (TaroCommitment taroTree, NonEmpty Asset.Asset)
mint issuance = do
    assets <- case Asset.mint issuance of
        Left err -> throwError $ AssetError err
        Right x -> return x
    assetCommitment <-
        runExceptT (commitAssets @assetTree assets) >>= \case
            Left err -> throwError $ CommitmentError err
            Right x -> return x
    taroCommitment <- commitAssetCommitments @taroTree [assetCommitment]
    return (taroCommitment, assets)

{- | The outer MS-SMT within the Taro protocol, whose leaves commit to an
 'AssetCommitment' set. Each asset commitment leaf in the tree is keyed by the
 concatenation of the asset version, the asset tree root, and the asset_sum.

 The leaves within the asset commitment inner MS-MST commit to an 'Asset' set.
 Each asset leaf in the inner tree is keyed by the asset group key if it
 exists, otherwise the asset id.
-}
data TaroCommitment t = TaroCommitment
    { version :: Asset.TaroVersion
    -- ^ The maximum Taro asset version within all of the assets committed.
    , treeRoot :: MSSMT.Branch AssetCommitmentLeaf
    -- ^ The root node of the MS-SMT containing all of the asset commitments.
    , tree :: Maybe t
    -- ^ The outer MS-SMT containing all of the asset commitments. If this is
    -- Nothing, the commitment cannot derive proofs.
    }
    deriving (Generic, Show, Eq)

type TaroTreeWriter t m = (MSSMT.TreeWriter m t, MSSMT.Key t ~ Digest SHA256, MSSMT.Elem t ~ AssetCommitmentLeaf)

{- | Constructs a new 'TaroCommitment' from the given 'AssetCommitments', which
 can be used to compute merkle proofs.
-}
commitAssetCommitments :: TaroTreeWriter t m => [AssetCommitment t'] -> m (TaroCommitment t)
commitAssetCommitments commitments = do
    emptyTree <- MSSMT.emptyM
    emptyTreeRoot <- MSSMT.rootNodeM emptyTree
    let emptyCommit =
            TaroCommitment
                { version = Asset.TaroV0
                , treeRoot = emptyTreeRoot
                , tree = Just emptyTree
                }
    foldM
        ( \TaroCommitment{version, treeRoot, tree} assetCommit@AssetCommitment{version = assetVersion, treeRoot = assetTreeRoot} -> do
            (treeRoot', tree') <- case tree of
                Nothing -> return (treeRoot, Nothing)
                Just t -> do
                    t' <-
                        MSSMT.insertM
                            (Asset.opaqueAssetId $ assetId assetCommit)
                            (assetCommitmentLeaf assetCommit)
                            (MSSMT.sumValue assetTreeRoot)
                            t
                    newTreeRoot <- MSSMT.rootNodeM t'
                    return (newTreeRoot, Just t')
            return $
                TaroCommitment
                    (max version assetVersion)
                    treeRoot'
                    tree'
        )
        emptyCommit
        commitments

{- | The inner MS-SMT within the Taro protocol, whose leaves commit to an
 'Asset' set. Each asset leaf in the inner tree is keyed by the asset group
 key if it exists, otherwise the asset id.
-}
data AssetCommitment t = AssetCommitment
    { version :: Asset.TaroVersion
    -- ^ The maximum Taro asset version of the assets committed.
    , assetId :: Asset.AssetId
    -- ^ The common identifier for all assets found within the asset commitment.
    , treeRoot :: MSSMT.Branch Asset.Asset
    -- ^ The root node of the MS-SMT containing all of the committed assets.
    , tree :: Maybe t
    -- ^ The inner MS-SMT containing all of the committed assets. If this is
    -- Nothing, the commitment cannot derive proofs.
    }
    deriving (Generic, Show, Eq)

{- | The serialised leaf representation of an 'AssetCommitment' within outer
 'TaroCommitment' MSSMT.
-}
data AssetCommitmentLeaf = AssetCommitmentLeaf
    { version :: Asset.TaroVersion
    -- ^ The maximum Taro asset version of the assets committed.
    , rootId :: Digest SHA256
    -- ^ The root identifier required to commit to this specific asset within
    -- the outer commitment.
    , rootSum :: Word64
    -- ^ The sum of all assets within the commitment leaf.
    }
    deriving (Generic, Show, Eq)

instance Binary AssetCommitmentLeaf where
    put AssetCommitmentLeaf{version, rootId, rootSum} = do
        put version
        putDigest rootId
        put rootSum
    get =
        AssetCommitmentLeaf
            <$> get
            <*> getDigest
            <*> get

assetCommitmentLeaf :: AssetCommitment t -> AssetCommitmentLeaf
assetCommitmentLeaf asset@AssetCommitment{version, treeRoot} =
    AssetCommitmentLeaf
        { version
        , rootId = assetRootId asset
        , rootSum = MSSMT.sumValue treeRoot
        }

assetRootId :: AssetCommitment t -> Digest SHA256
assetRootId AssetCommitment{assetId, treeRoot = root@MSSMT.Branch{left, right}} =
    hashFinalize $
        hashInit
            `hashUpdate` Asset.opaqueAssetId assetId
            `hashUpdate` MSSMT.digest left
            `hashUpdate` MSSMT.digest right
            `hashUpdate` (fromW64BE $ MSSMT.sumValue root :: ByteString)

data AssetError
    = AssetGenesisMismatch Asset.Genesis Asset.Genesis
    | AssetGroupKeyMismatch (Maybe Asset.GroupKey) (Maybe Asset.GroupKey)
    | AssetGenesisNotMemberOfGroup Asset.Genesis Asset.GroupKey
    | AssetScriptKeyNotUnique (Digest SHA256)
    deriving (Generic, Show, Eq)

type AssetTreeWriter t m = (MSSMT.TreeWriter m t, MSSMT.Key t ~ Digest SHA256, MSSMT.Elem t ~ Asset.Asset)

{- | Constructs a new 'AssetCommitment' from the given 'Asset' set, which can be
 used to compute merkle proofs. This function validates that the assets:
 * all related within the same asset group or have the same asset ID
 * all have unique asset commitment keys within the asset commitment
 and will return an error otherwise.
-}
commitAssets :: forall t m. (AssetTreeWriter t m, MonadError AssetError m) => NonEmpty Asset.Asset -> m (AssetCommitment t)
commitAssets (headAsset@Asset.Asset{assetGenesis = expectedGenesis, assetGroupKey = expectedGroupKey} :| tailAssets) = do
    commitment <- commitAsset headAsset
    foldM
        ( \AssetCommitment{version, assetId, treeRoot, tree} asset@Asset.Asset{amount, assetGenesis, assetGroupKey} -> do
            let key = assetCommitmentKey asset
            unless (expectedGroupKey == assetGroupKey) $
                throwError $
                    AssetGroupKeyMismatch expectedGroupKey assetGroupKey
            case expectedGroupKey of
                Nothing ->
                    unless (expectedGenesis == assetGenesis) $
                        throwError $
                            AssetGenesisMismatch expectedGenesis assetGenesis
                Just groupKey ->
                    unless (assetGenesis `Asset.isMemberOfGroup` groupKey) $
                        throwError $
                            AssetGenesisNotMemberOfGroup assetGenesis groupKey
            (newTreeRoot, newTree) <- case tree of
                Nothing -> return (treeRoot, Nothing)
                Just t -> do
                    MSSMT.memberM key t >>= \case
                        True -> throwError $ AssetScriptKeyNotUnique key
                        _ -> return ()
                    t' <- MSSMT.insertM key asset amount t
                    newTreeRoot <- MSSMT.rootNodeM t'
                    return (newTreeRoot, Just t')
            return $
                AssetCommitment
                    (max version $ Asset.taroVersion asset)
                    assetId
                    newTreeRoot
                    newTree
        )
        commitment
        tailAssets

{- | Construct a new asset commitment for a single asset, with the ability to
 compute merkle proofs.
-}
commitAsset :: forall t m. (MSSMT.TreeWriter m t, MSSMT.Key t ~ Digest SHA256, MSSMT.Elem t ~ Asset.Asset) => Asset.Asset -> m (AssetCommitment t)
commitAsset asset@Asset.Asset{taroVersion, assetGenesis, amount} = do
    let key = assetCommitmentKey asset
    tree <- MSSMT.insertM key asset amount =<< MSSMT.emptyM
    treeRoot <- MSSMT.rootNodeM tree
    return $
        AssetCommitment
            { version = taroVersion
            , assetId = Asset.toAssetId assetGenesis
            , treeRoot
            , tree = Just tree
            }

-- | The owner of an 'Asset' within an 'AssetCommitment'.
assetCommitmentKey :: Asset.Asset -> Digest SHA256
assetCommitmentKey Asset.Asset{assetGenesis, assetGroupKey, assetScriptKey} =
    let keyBytes = encode $ XOnlyPubKey assetScriptKey
     in case assetGroupKey of
            Nothing -> hash $ BSL.toStrict keyBytes
            _ ->
                hashFinalize $
                    hashInit
                        `hashUpdates` fmap
                            BSL.toStrict
                            [ encode $ Asset.toAssetId assetGenesis
                            , keyBytes
                            ]
