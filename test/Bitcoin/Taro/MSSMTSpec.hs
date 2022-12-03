{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Bitcoin.Taro.MSSMTSpec where

import Bitcoin
import Bitcoin.Taro.MSSMT as MSSMT
import Bitcoin.Taro.TestUtils
import Bitcoin.Taro.Util (RawBytes (..))
import Control.Monad (foldM_, forM, forM_)
import Crypto.Hash (Digest, SHA256, digestFromByteString)
import Data.Aeson (FromJSON, (.:))
import qualified Data.Aeson as JSON
import qualified Data.Aeson.Types as JSON
import Data.Binary (Binary)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BSL
import Data.Maybe (fromJust, isJust)
import qualified Data.Vector as Vector
import Data.Void (Void)
import Data.Word (Word16, Word64)
import GHC.Generics (Generic)
import Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Paths_bitcoin_taro (getDataFileName)
import Test.Hspec
import Test.Tasty
import Test.Tasty.Hedgehog
import Prelude hiding (lookup)

spec_EmptyTree :: Spec
spec_EmptyTree = describe "Empty tree test vectors" $ do
    emptyDigests <- runIO $ do
        emptyTreeDigestsFile <- getDataFileName "test/vectors/Tree.empty.digests.json"
        digests <- fromJust <$> JSON.decodeFileStrict emptyTreeDigestsFile
        return $ fromJust . digestFromByteString . fromJust . decodeHex <$> digests
    it "should generate the empty leaf" $ do
        digest (emptyLeaf @Void) `shouldBe` head emptyDigests
        sumValue (emptyLeaf @Void) `shouldBe` 0
    it "should generate empty branches" $
        forM_ (zip [0 ..] $ tail emptyDigests) $ \(i, branchDigest) -> do
            Just branch <- pure $ emptyBranches @Void Vector.!? i
            digest branch `shouldBe` branchDigest
            sumValue branch `shouldBe` 0

data TreeCommitmentTestVector = TreeCommitmentTestVector
    { leafKey :: ByteString
    , leafValue :: RawBytes
    , leafSum :: Word64
    , leafHash :: Digest SHA256
    , rootSum :: Word64
    , rootHash :: Digest SHA256
    }
    deriving (Generic)

instance FromJSON TreeCommitmentTestVector where
    parseJSON (JSON.Object v) =
        TreeCommitmentTestVector
            <$> parseHex "leafKey"
            <*> (RawBytes . BSL.fromStrict <$> parseHex "leafValue")
            <*> v
                .: "leafSum"
            <*> parseDigest "leafHash"
            <*> v
                .: "rootSum"
            <*> parseDigest "rootHash"
      where
        parseDigest k = do
            b <- parseHex k
            Just hash <- pure $ digestFromByteString b
            return hash
        parseHex k = do
            JSON.String t <- v .: k
            Just b <- pure $ decodeHex t
            return b
    parseJSON invalid =
        JSON.prependFailure
            "parsing TreeCommitmentTestVector failed, "
            (JSON.typeMismatch "Object" invalid)

spec_TreeCommitments :: Spec
spec_TreeCommitments = describe "Tree commitment test vectors" $ do
    treeCommitments :: [TreeCommitmentTestVector] <- runIO $ do
        treeCommitmentsFile <- getDataFileName "test/vectors/Tree.commitments.json"
        fromJust <$> JSON.decodeFileStrict treeCommitmentsFile
    it "should build tree with valid commitments" $ do
        foldM_
            ( \tree TreeCommitmentTestVector{..} -> do
                digest Leaf{value = Just leafValue, leafSum, leafDigest = Nothing} `shouldBe` leafHash
                let tree' = insert leafKey leafValue leafSum tree
                digest (rootNode tree') `shouldBe` rootHash
                sumValue (rootNode tree') `shouldBe` rootSum
                return tree'
            )
            emptyMapMSSMT
            treeCommitments
    it "should destruct tree with valid commitments" $ do
        let completeTree =
                foldr
                    (\TreeCommitmentTestVector{..} -> insert leafKey leafValue leafSum)
                    emptyMapMSSMT
                    treeCommitments
        foldM_
            ( \tree TreeCommitmentTestVector{..} -> do
                digest (rootNode tree) `shouldBe` rootHash
                sumValue (rootNode tree) `shouldBe` rootSum
                digest Leaf{value = Just leafValue, leafSum, leafDigest = Nothing} `shouldBe` leafHash
                return $ delete leafKey tree
            )
            completeTree
            (reverse treeCommitments)

test_MerkleProof_encodeDecodeInverse :: TestTree
test_MerkleProof_encodeDecodeInverse = encodeDecodeInverse $ genMerkleProof @()

test_MerkleProof_compressDecompressInverse :: TestTree
test_MerkleProof_compressDecompressInverse =
    testPropertyNamed
        "forall (x :: MerkleProof) . decompressMerkleProof (compressMerkleProof x) == x"
        "prop_MerkleProof_compress_decompress_inverse"
        $ property
        $ do
            x <- forAll $ genCompressibleMerkleProof @() (Range.singleton 30)
            decompressMerkleProof (compressMerkleProof x) === x

type TestMSSMT = MapMSSMT ByteString String

test_MSSMT_properties :: TestTree
test_MSSMT_properties =
    testGroup
        "Merkle Sum Sparse Merkle Tree properties"
        [ testPropertyNamed
            "forall k v s t u . lookup k (insert k v s t <> u) = Just (v,s)"
            "MSSMT_inserts_members"
            $ property
            $ do
                k <- forAll genKey
                v <- forAll genValue
                s <- forAll genSum
                t <- fromListTest <$> forAll (genTestTreeList (Range.linear 0 10))
                u <- fromListTest <$> forAll (genTestTreeList (Range.linear 0 10))
                lookup k (insert k v s t <> u) === Just (v, s)
        , testPropertyNamed
            "forall k t . member k t = isJust (lookup k t)"
            "MSSMT_member_is_just_lookup"
            $ property
            $ do
                k <- forAll genKey
                t <- fromListTest <$> forAll (genTestTreeList (Range.linear 0 10))
                member k t === isJust (lookup k t)
        , testPropertyNamed
            "forall k t u . lookup k (delete k t <> u) = Nothing"
            "MSSMT_deletes_members"
            $ property
            $ do
                k <- forAll genKey
                t <- fromListTest <$> forAll (genTestTreeList (Range.linear 0 10))
                u <- fromListTest <$> forAll (genTestTreeList (Range.linear 0 10))
                lookup k (delete k t <> u) === Nothing
        , testPropertyNamed
            "forall k v s t u . null (delete k (insert k v s mempty :: TestMSSMT))"
            "MSSMT_delete_inverts_insert"
            $ property
            $ do
                k <- forAll genKey
                v <- forAll genValue
                s <- forAll genSum
                assert $ null (delete k (insert k v s mempty :: TestMSSMT))
        , testPropertyNamed
            "forall t u . sumValue (rootNode (t <> u)) = sumValue (rootNode t) + sumValue (rootNode u)"
            "MSSMT_root_sum_is_additive"
            $ property
            $ do
                t <- fromListTest <$> forAll (genTestTreeList (Range.linear 0 10))
                u <- fromListTest <$> forAll (genTestTreeList (Range.linear 0 10))
                sumValue (rootNode (t <> u)) === sumValue (rootNode t) + sumValue (rootNode u)
        , testPropertyNamed
            "forall t u . toCommitment (rootNode (t <> u)) = toCommitment (rootNode (u <> t))"
            "MSSMT_history_independence"
            $ property
            $ do
                t <- fromListTest <$> forAll (genTestTreeList (Range.linear 0 10))
                u <- fromListTest <$> forAll (genTestTreeList (Range.linear 0 10))
                toCommitment (rootNode (t <> u)) === toCommitment (rootNode (u <> t))
        , testPropertyNamed
            "forall k v s t u . verifyMerkleProof (rootNode t') k leaf (generateMerkleProof k t') where t' = insert k v s t <> u; leaf = Leaf (Just v) s Nothing"
            "MSSMT_accept_valid_inclusion_merkle_proof"
            $ property
            $ do
                k <- forAll genKey
                v <- forAll genValue
                s <- forAll genSum
                t <- fromListTest <$> forAll (genTestTreeList (Range.linear 0 10))
                u <- fromListTest <$> forAll (genTestTreeList (Range.linear 0 10))
                let t' = insert k v s t <> u
                    leaf = Leaf{value = Just v, MSSMT.leafSum = s, leafDigest = Nothing}
                assert $ verifyMerkleProof (rootNode t') k leaf (generateMerkleProof k t')
        , testPropertyNamed
            "forall k t . verifyMerkleProof (rootNode t') k emptyLeaf (generateMerkleProof k t') where t' = delete k t"
            "MSSMT_accept_valid_exclusion_merkle_proof"
            $ property
            $ do
                k <- forAll genKey
                t <- fromListTest <$> forAll (genTestTreeList (Range.linear 0 10))
                let t' = delete k t
                assert $ verifyMerkleProof (rootNode t') k emptyLeaf (generateMerkleProof k t')
        ]

insertTuple :: (ByteString, String, Word64) -> TestMSSMT -> TestMSSMT
insertTuple (k, v, s) = insert k v s

genTestTree :: Range Int -> Gen TestMSSMT
genTestTree range = fromListTest <$> Gen.list range genLeafTuple

genTestTreeList :: Range Int -> Gen [(ByteString, String, Word64)]
genTestTreeList range = Gen.list range genLeafTuple

fromListTest :: Foldable t => t (ByteString, String, Word64) -> TestMSSMT
fromListTest = fromList

genLeafTuple :: Gen (ByteString, String, Word64)
genLeafTuple =
    (,,)
        <$> genKey
        <*> genValue
        <*> genSum

genKey :: Gen ByteString
genKey = Gen.bytes (Range.singleton 32)

genValue :: Gen String
genValue = Gen.string (Range.linear 0 10) Gen.alphaNum

genSum :: Gen Word64
genSum = Gen.word64 (Range.linear 0 10000)

genRootNode :: Gen (Node a)
genRootNode = BranchCommitment <$> genCommitment

genMerkleProof :: Gen (MerkleProof a)
genMerkleProof = MerkleProof <$> Gen.list (Range.singleton 256) genCommitment

genCompressibleMerkleProof :: Binary a => Range Word16 -> Gen (MerkleProof a)
genCompressibleMerkleProof expectedCompressedLength =
    MerkleProof <$> do
        forM [0 :: Word16 .. maxTreeHeight - 1] $ \height -> do
            r <- Gen.integral expectedCompressedLength
            n <- Gen.integral (Range.linear 0 $ maxTreeHeight - 1)
            if r < n
                then pure $ toCommitment $ fromJust $ lookupEmptyNode height
                else genCommitment

genCommitment :: Gen (Commitment a)
genCommitment =
    Commitment
        <$> genDigest
        <*> Gen.word64 Range.linearBounded
