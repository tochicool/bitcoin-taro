{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Bitcoin.Taro.MSSMT where

import Bitcoin.Block.Merkle (boolsToWord8, decodeMerkleFlags, encodeMerkleFlags, splitIn)
import qualified Bitcoin.Taro.TLV as TLV
import Bitcoin.Taro.Util (bitsBytes, bytes, getDigest, putDigest)
import Control.Applicative ((<|>))
import Control.Monad (foldM, replicateM)
import Crypto.Hash (Digest, HashAlgorithm (hashDigestSize), hashFinalize, hashInit, hashUpdate)
import Crypto.Hash.Algorithms
import Data.Binary (Binary (get, put), encode)
import Data.Bits (FiniteBits (finiteBitSize), testBit)
import Data.ByteArray (ByteArray, ByteArrayAccess)
import qualified Data.ByteArray as BA
import Data.ByteArray.Mapping (fromW64BE)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BSL
import Data.Foldable (foldl', traverse_)
import qualified Data.Foldable as Foldable
import Data.Functor.Identity
import Data.Kind (Type)
import Data.List (unfoldr)
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Maybe (fromMaybe)
import qualified Data.Sequence as Seq
import Data.Vector (Vector)
import qualified Data.Vector as Vector
import Data.Word (Word16, Word64)
import GHC.Generics (Generic)
import Prelude hiding (lookup)

-- | A reader of an MS-SMT of elements 'a' over the monad 'm'.
class Monad m => TreeReader m a where
    type Key a :: Type
    type Elem a :: Type

    -- | Retrieve the root node of the MS-SMT. This may yield the empty root node
    -- if the tree contains no elements.
    rootNodeM :: a -> m (Branch (Elem a))

    -- | Retrieve the nodes of the left and right children of the branch with the
    -- given digest in the MS-SMT, respectively. Both nodes may be empty if no
    -- such branch exists.
    lookupBranchM :: Integral i => i -> Digest SHA256 -> a -> m (Branch (Elem a))

-- | A writer of an MS-SMT of elements 'a' over the monad 'm'.
class TreeReader m a => TreeWriter m a where
    -- | Create a new empty tree
    emptyM :: m a

    -- | Replace the root node of the tree with the given branch.
    updateRootM :: Branch (Elem a) -> a -> m a

    -- | Insert the given branch into the tree.
    insertBranchM :: Branch (Elem a) -> a -> m a

    -- | Remove the given branch from the tree
    deleteBranchM :: Digest SHA256 -> a -> m a

    -- | Insert the given leaf into the tree.
    insertLeafM :: Leaf (Elem a) -> a -> m a

    -- | Remove the given leaf from the tree.
    deleteLeafM :: Digest SHA256 -> a -> m a

data MapMSSMT (k :: Type) a = MapMSSMT
    { root :: Branch a
    , branches :: Map (Digest SHA256) (Branch a)
    , leaves :: Map (Digest SHA256) (Leaf a)
    }
    deriving (Generic, Eq)

instance Binary a => Show (MapMSSMT k a) where
    show MapMSSMT{root} = show root

emptyMapMSSMT :: MapMSSMT k a
emptyMapMSSMT =
    MapMSSMT
        { root = Vector.last emptyBranches
        , branches = mempty
        , leaves = mempty
        }

instance Foldable (MapMSSMT k) where
    foldr f z MapMSSMT{leaves} =
        foldr f z $
            foldr
                ( \case
                    Leaf{value = Just x} -> (x :)
                    _ -> id
                )
                []
                leaves

instance (ByteArray k, Binary v) => Semigroup (MapMSSMT k v) where
    t <> u =
        foldr
            ( \case
                (k, Leaf{value = Just v, leafSum = s}) -> insert k v s
                _ -> id
            )
            t
            $ toList u

instance (ByteArray k, Binary v) => Monoid (MapMSSMT k v) where
    mempty = emptyMapMSSMT

instance (Monad m) => TreeReader m (MapMSSMT k a) where
    type Key (MapMSSMT k _) = k
    type Elem (MapMSSMT _ a) = a
    rootNodeM MapMSSMT{root} = pure root
    lookupBranchM height key MapMSSMT{branches} =
        pure $
            fromMaybe emptyBranch $
                Map.lookup key branches <|> emptyBranches Vector.!? fromIntegral (height - 1)

instance (Monad m, Binary a) => TreeWriter m (MapMSSMT k a) where
    emptyM = pure emptyMapMSSMT
    updateRootM newRoot tree = pure $ tree{root = newRoot}
    insertBranchM branch tree = pure $ tree{branches = Map.insert (digest branch) branch $ branches tree}
    deleteBranchM key tree = pure $ tree{branches = Map.delete key $ branches tree}
    insertLeafM leaf tree = pure $ tree{leaves = Map.insert (digest leaf) leaf $ leaves tree}
    deleteLeafM key tree = pure $ tree{leaves = Map.delete key $ leaves tree}

class IsCommitment c where
    type NodeElem c :: Type
    toCommitment :: c -> Commitment (NodeElem c)
    toCommitment n =
        Commitment
            { commitDigest = digest n
            , commitSum = sumValue n
            }
    digest :: c -> Digest SHA256
    digest = commitDigest . toCommitment
    sumValue :: c -> Word64
    sumValue = commitSum . toCommitment

class IsCommitment n => IsNode n where
    toNode :: n -> Node (NodeElem n)
    compact :: n -> n
    compact = id

data Node a
    = LeafNode (Leaf a)
    | BranchNode (Branch a)
    | BranchCommitment (Commitment a)
    | LeafCommitment (Commitment a)
    deriving (Generic)

instance Binary a => Show (Node a) where
    show = show . toCommitment

instance Binary a => IsCommitment (Node a) where
    type NodeElem (Node a) = a
    toCommitment = \case
        LeafNode leaf -> toCommitment leaf
        BranchNode branch -> toCommitment branch
        BranchCommitment c -> c
        LeafCommitment c -> c

instance Binary a => IsNode (Node a) where
    toNode = id
    compact = \case
        BranchNode branch -> BranchNode $ compact branch
        LeafNode leaf -> LeafNode $ compact leaf
        n -> n

instance Binary a => Eq (Node a) where
    u == v = toCommitment u == toCommitment v

data Leaf a = Leaf
    { value :: Maybe a
    , leafSum :: Word64
    , leafDigest :: Maybe (Digest SHA256)
    }
    deriving (Generic, Show, Eq)

instance Binary a => IsCommitment (Leaf a) where
    type NodeElem (Leaf a) = a
    digest Leaf{value, leafSum} =
        hashFinalize $
            maybe hashInit (hashUpdate hashInit . BSL.toStrict . encode) value
                `hashUpdate` (fromW64BE leafSum :: ByteString)
    sumValue Leaf{leafSum} = leafSum

instance Binary a => IsNode (Leaf a) where
    toNode = LeafNode
    compact = id

data Branch a = Branch
    { left :: Node a
    , right :: Node a
    , commitment :: Maybe (Commitment a)
    }
    deriving (Generic, Show, Eq)

instance Binary a => IsCommitment (Branch a) where
    type NodeElem (Branch a) = a
    toCommitment = \case
        Branch{left, right, commitment} -> case commitment of
            Just c -> c
            Nothing ->
                let commitDigest =
                        hashFinalize $
                            hashInit
                                `hashUpdate` digest left
                                `hashUpdate` digest right
                                `hashUpdate` (fromW64BE commitSum :: ByteString)
                    commitSum = sumValue left + sumValue right
                 in Commitment{commitDigest, commitSum}

instance Binary a => IsNode (Branch a) where
    toNode = BranchNode
    compact = \case
        Branch{left, right, commitment = Nothing} ->
            let left' = compactChild left
                right' = compactChild right
                branch = Branch{left = left', right = right', commitment = Nothing}
             in branch{commitment = Just $ toCommitment branch}
        n -> n
      where
        compactChild = \case
            BranchNode branch -> BranchCommitment (toCommitment branch)
            n -> n

data Commitment (a :: Type) = Commitment
    { commitDigest :: Digest SHA256
    , commitSum :: Word64
    }
    deriving (Generic, Show, Eq)

instance IsCommitment (Commitment a) where
    type NodeElem (Commitment a) = a
    toCommitment = id

instance TLV.StaticSize (Commitment a) where
    staticSize = fromIntegral $ hashDigestSize SHA256 + bitsBytes @Word64

instance Binary (Commitment a) where
    put (Commitment commitDigest commitSum) = do
        putDigest commitDigest
        put commitSum
    get =
        Commitment
            <$> getDigest
            <*> get

maxTreeHeight :: Integral i => i
maxTreeHeight = fromIntegral $ hashDigestSize SHA256 * 8

emptyBranches :: Vector (Branch a)
emptyBranches =
    Vector.unfoldrExactN
        maxTreeHeight
        ( \(previousNode, previousCommitment) ->
            let commitSum = 0
                previousDigest = digest previousCommitment
                commitDigest =
                    hashFinalize $
                        hashInit
                            `hashUpdate` previousDigest
                            `hashUpdate` previousDigest
                            `hashUpdate` (fromW64BE commitSum :: ByteString)
                commitment = Commitment{commitSum, commitDigest}
                branch = Branch{left = previousNode, right = previousNode, commitment = Just commitment}
             in (branch, (BranchNode branch, commitment))
        )
        (LeafNode emptyLeaf, emptyLeafCommitment)

emptyBranch :: Branch a
emptyBranch = Branch{left = leaf, right = LeafNode emptyLeaf, commitment = Nothing}
  where
    leaf = LeafNode emptyLeaf

emptyLeaf :: Leaf a
emptyLeaf = Leaf{value = Nothing, leafSum = 0, leafDigest = Nothing}

emptyLeafCommitment :: Commitment a
emptyLeafCommitment =
    Commitment
        { commitSum = 0
        , commitDigest =
            hashFinalize $
                hashInit
                    `hashUpdate` (fromW64BE 0 :: ByteString)
        }

lookupEmptyNode :: (Integral i, Binary a) => i -> Maybe (Node a)
lookupEmptyNode = \case
    0 -> Just $ toNode emptyLeaf
    height -> toNode <$> emptyBranches Vector.!? fromIntegral (height - 1)

nodeIsEmpty :: (Integral i, IsCommitment n) => i -> n -> Bool
nodeIsEmpty height = digestIsEmpty height . digest

digestIsEmpty :: Integral i => i -> Digest SHA256 -> Bool
digestIsEmpty height nodeDigest = case height of
    0 -> nodeDigest == digest (emptyLeaf @ByteString)
    _ -> Just nodeDigest == fmap digest (emptyBranches @ByteString Vector.!? fromIntegral (height - 1))

lookupM :: (TreeReader m t, Binary (Elem t), ByteArrayAccess (Key t)) => Key t -> t -> m (Maybe (Elem t, Word64))
lookupM key t =
    lookupNodeM key t >>= \case
        LeafNode Leaf{value = Just v, leafSum} -> pure $ Just (v, leafSum)
        _ -> pure Nothing

lookupNodeM :: (TreeReader m t, ByteArrayAccess (Key t), Binary (Elem t)) => Key t -> t -> m (Node (Elem t))
lookupNodeM key t = do
    root <- rootNodeM t
    foldM
        ( \current (height, isLeftSibling) -> do
            Branch{left, right} <- lookupBranchM height (digest current) t
            return $ if isLeftSibling then right else left
        )
        (toNode root)
        (walkDown key)

memberM :: (TreeReader m t, ByteArrayAccess (Key t), Binary (Elem t)) => Key t -> t -> m Bool
memberM key t = not . nodeIsEmpty (0 :: Integer) <$> lookupNodeM key t

toListM :: (TreeReader m t, Binary (Elem t)) => ByteArray (Key t) => t -> m [(Key t, Leaf (Elem t))]
toListM t = do
    root <- rootNodeM t
    toListM' (maxTreeHeight :: Int) Seq.empty $ toNode root
  where
    toListM' height path root = do
        Branch{left, right} <- lookupBranchM height (digest root) t
        (<>)
            <$> toListM'' (height - 1) (path Seq.|> False) left
            <*> toListM'' (height - 1) (path Seq.|> True) right
    toListM'' height path n = case n of
        LeafNode leaf@Leaf{value = Just{}} -> return [(BA.pack $ boolsToWord8 <$> splitIn bytes (Foldable.toList path), leaf)]
        LeafNode{} -> return []
        _ | nodeIsEmpty height n || height < 0 -> return []
        _ | otherwise -> toListM' height path n

insertM :: (TreeWriter m t, ByteArrayAccess (Key t), Binary (Elem t)) => Key t -> Elem t -> Word64 -> t -> m t
insertM key value = updateM key (Just value)

updateM :: (TreeWriter m t, ByteArrayAccess (Key t), Binary (Elem t)) => Key t -> Maybe (Elem t) -> Word64 -> t -> m t
updateM key value leafSum t = do
    root <- rootNodeM t
    (leaf, insertionPath) <-
        foldM
            ( \(current, insertionPath) (height, downRight) -> do
                Branch{left, right} <- lookupBranchM height (digest current) t
                return $
                    if downRight
                        then (right, (left, current, downRight) : insertionPath)
                        else (left, (right, current, downRight) : insertionPath)
            )
            (toNode root, [])
            (walkDown key)
    let newLeaf = Leaf{value, leafSum, leafDigest = Nothing}
    (t', root', _) <-
        foldM
            ( \(tree, current, height) (sibling, parent, isLeftSibling) -> do
                let (left, right) =
                        if isLeftSibling
                            then (sibling, current)
                            else (current, sibling)
                    newParent = compact $ Branch{left, right, commitment = Nothing}
                tree' <-
                    if nodeIsEmpty height parent
                        then return tree
                        else deleteBranchM (digest parent) tree
                tree'' <-
                    if nodeIsEmpty height newParent
                        then return tree
                        else insertBranchM newParent tree'
                return (tree'', toNode newParent, height + 1)
            )
            (t, toNode newLeaf, 1 :: Int)
            insertionPath
    t'' <-
        if nodeIsEmpty (0 :: Int) newLeaf
            then deleteLeafM (digest leaf) t'
            else insertLeafM newLeaf t'
    case root' of
        BranchNode branch -> updateRootM branch t''
        _ -> return t''

deleteM :: (TreeWriter m t, ByteArrayAccess (Key t), Binary (Elem t)) => Key t -> t -> m t
deleteM key = updateM key Nothing 0

fromListM :: (Foldable f, TreeWriter m t, ByteArrayAccess (Key t), Binary (Elem t)) => f (Key t, Elem t, Word64) -> m t
fromListM xs = do
    tree <- emptyM
    foldM (\t (k, v, s) -> insertM k v s t) tree xs

newtype MerkleProof a = MerkleProof
    { proof :: [Commitment a]
    }
    deriving (Generic, Eq)

instance Show a => Show (MerkleProof a) where
    showsPrec n p = ("decompressMerkleProof " ++) . showsPrec n (compressMerkleProof p)

instance Binary a => Binary (MerkleProof a) where
    put = put . compressMerkleProof
    get = decompressMerkleProof <$> get

data CompressedMerkleProof a = CompressedMerkleProof
    { compressedLength :: Word16
    , compressedProof :: [Commitment a]
    , compressionBits :: [Bool]
    }
    deriving (Generic, Show, Eq)

instance Binary (CompressedMerkleProof a) where
    put CompressedMerkleProof{..} = do
        put compressedLength
        put `traverse_` compressedProof
        put `traverse_` encodeMerkleFlags compressionBits
    get = do
        compressedLength <- get
        CompressedMerkleProof compressedLength
            <$> replicateM (fromIntegral compressedLength) get
            <*> (decodeMerkleFlags <$> replicateM (hashDigestSize SHA256) get)

compressMerkleProof :: MerkleProof a -> CompressedMerkleProof a
compressMerkleProof MerkleProof{proof} =
    foldr
        ( \(commitment, height) p@CompressedMerkleProof{..} ->
            if nodeIsEmpty height commitment
                then p{compressionBits = True : compressionBits}
                else p{compressionBits = False : compressionBits, compressedLength = compressedLength + 1, compressedProof = commitment : compressedProof}
        )
        (CompressedMerkleProof 0 [] [])
        (zip proof [0 :: Int ..])

decompressMerkleProof :: Binary a => CompressedMerkleProof a -> MerkleProof a
decompressMerkleProof proof =
    MerkleProof $
        unfoldr
            ( \case
                (height, p@CompressedMerkleProof{compressionBits = compressed : compressionBits', compressedProof})
                    | compressed
                    , Just proofNode <- lookupEmptyNode height
                    , height < maxTreeHeight ->
                        Just (toCommitment proofNode, (height + 1, p{compressionBits = compressionBits'}))
                    | (proofHash : compressedProof') <- compressedProof ->
                        Just (proofHash, (height + 1, p{compressionBits = compressionBits', compressedProof = compressedProof'}))
                _ | otherwise -> Nothing
            )
            (0 :: Int, proof)

generateMerkleProofM :: (TreeReader m t, ByteArrayAccess (Key t), Binary (Elem t)) => Key t -> t -> m (MerkleProof (Elem t))
generateMerkleProofM key t = do
    root <- rootNodeM t
    (_, proof) <-
        foldM
            ( \(current, proof) (height, isLeftSibling) -> do
                Branch{left, right} <- lookupBranchM height (digest current) t
                let (sibling, next) =
                        if isLeftSibling
                            then (left, right)
                            else (right, left)
                return (next, toCommitment sibling : proof)
            )
            (toNode root, [])
            (walkDown key)
    return MerkleProof{proof}

verifyMerkleProof :: (IsNode n, Binary (NodeElem n), ByteArrayAccess k) => n -> k -> Leaf (NodeElem n) -> MerkleProof (NodeElem n) -> Bool
verifyMerkleProof root key leaf proof =
    toCommitment root == toCommitment (computeMerkleRoot key leaf proof)

computeMerkleRoot :: (Binary (NodeElem n), IsNode n, ByteArrayAccess a) => a -> n -> MerkleProof (NodeElem n) -> Node (NodeElem n)
computeMerkleRoot key leaf = \case
    MerkleProof (p : ps) ->
        foldl'
            ( \current (sibling, isLeftSibling) ->
                let (left, right)
                        | isLeftSibling = (sibling, current)
                        | otherwise = (current, sibling)
                 in toNode $ Branch{left, right, commitment = Nothing}
            )
            (toNode leaf)
            (zip (LeafCommitment p : (BranchCommitment <$> ps)) (reverse $ byteArrayBits key))
    _ -> toNode $ Vector.last emptyBranches

walkDown :: ByteArrayAccess a => a -> [(Int, Bool)]
walkDown key = zip [maxTreeHeight, maxTreeHeight - 1 ..] (byteArrayBits key)

binaryBits :: Binary a => a -> [Bool]
binaryBits = byteArrayBits . BSL.toStrict . encode

byteArrayBits :: ByteArrayAccess a => a -> [Bool]
byteArrayBits = concatMap finiteBits . BA.unpack

finiteBits :: FiniteBits a => a -> [Bool]
finiteBits x = [testBit x i | i <- [0 .. finiteBitSize x - 1]]

--------------------------------------------------------------------------------

rootNode :: TreeReader Identity t => t -> Branch (Elem t)
rootNode = runIdentity . rootNodeM

lookupBranch :: (TreeReader Identity t, Integral i) => i -> Digest SHA256 -> t -> Branch (Elem t)
lookupBranch height k = runIdentity . lookupBranchM height k

member :: (TreeReader Identity t, ByteArrayAccess (Key t), Binary (Elem t)) => Key t -> t -> Bool
member k = runIdentity . memberM k

lookup :: (TreeReader Identity t, ByteArrayAccess (Key t), Binary (Elem t)) => Key t -> t -> Maybe (Elem t, Word64)
lookup k = runIdentity . lookupM k

lookupNode :: (TreeReader Identity t, ByteArrayAccess (Key t), Binary (Elem t)) => Key t -> t -> Node (Elem t)
lookupNode k = runIdentity . lookupNodeM k

toList :: (TreeReader Identity t, Binary (Elem t)) => ByteArray (Key t) => t -> [(Key t, Leaf (Elem t))]
toList = runIdentity . toListM

insert :: (TreeWriter Identity t, ByteArrayAccess (Key t), Binary (Elem t)) => Key t -> Elem t -> Word64 -> t -> t
insert k v s = runIdentity . insertM k v s

delete :: (TreeWriter Identity t, ByteArrayAccess (Key t), Binary (Elem t)) => Key t -> t -> t
delete k = runIdentity . deleteM k

fromList :: (Foldable f, TreeWriter Identity t, ByteArrayAccess (Key t), Binary (Elem t)) => f (Key t, Elem t, Word64) -> t
fromList = runIdentity . fromListM

empty :: TreeWriter Identity t => t
empty = runIdentity emptyM

updateRoot :: TreeWriter Identity t => Branch (Elem t) -> t -> t
updateRoot branch = runIdentity . updateRootM branch

insertBranch :: TreeWriter Identity t => Branch (Elem t) -> t -> t
insertBranch branch = runIdentity . insertBranchM branch

deleteBranch :: TreeWriter Identity t => Digest SHA256 -> t -> t
deleteBranch k = runIdentity . deleteBranchM k

insertLeaf :: TreeWriter Identity t => Leaf (Elem t) -> t -> t
insertLeaf leaf = runIdentity . insertLeafM leaf

deleteLeaf :: TreeWriter Identity t => Digest SHA256 -> t -> t
deleteLeaf k = runIdentity . deleteLeafM k

generateMerkleProof :: (TreeReader Identity t, ByteArrayAccess (Key t), Binary (Elem t)) => Key t -> t -> MerkleProof (Elem t)
generateMerkleProof k = runIdentity . generateMerkleProofM k
