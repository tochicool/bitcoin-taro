{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Bitcoin.Taro.TestUtils where

import Bitcoin
import Bitcoin.Taro.Util (ParityPubKey (..))
import Control.Monad (replicateM)
import Crypto.Hash (Digest, HashAlgorithm (..), digestFromByteString)
import Crypto.Hash.IO (HashDigestSize)
import Data.Binary (Binary)
import qualified Data.Binary as Bin
import qualified Data.ByteString.Lazy as BSL
import Data.Char (isSpace)
import Data.Data (Proxy (..), Typeable)
import Data.String (fromString)
import Data.Typeable (typeRep)
import GHC.TypeLits (natVal)
import GHC.TypeNats (KnownNat)
import Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Test.Tasty
import Test.Tasty.Hedgehog

encodeDecodeInverseWith :: forall a. (Show a, Eq a, Binary a, Typeable a) => TestLimit -> Gen a -> TestTree
encodeDecodeInverseWith n gen =
  testPropertyNamed
    ("forall (x :: " <> dataType <> ") . decode (encode x) == x")
    ("prop_" <> fromString (propName dataType) <> "_encode_decode_inverse")
    $ withTests n $
      property $
        do
          x <- forAll gen
          Bin.decode (Bin.encode x) === x
  where
    dataType = show $ typeRep (Proxy :: Proxy a)

testPropertyNamed' :: TestName -> Property -> TestTree
testPropertyNamed' name = testPropertyNamed name (fromString $ propName name)

propName :: String -> String
propName = fmap $ \case
  x
    | isSpace x -> '_'
    | otherwise -> x

encodeDecodeInverse :: forall a. (Show a, Eq a, Binary a, Typeable a) => Gen a -> TestTree
encodeDecodeInverse = encodeDecodeInverseWith 100

genDigest :: forall alg. (HashAlgorithm alg, KnownNat (HashDigestSize alg)) => Gen (Digest alg)
genDigest = Gen.just $ digestFromByteString <$> Gen.bytes (Range.singleton (fromIntegral $ natVal $ Proxy @(HashDigestSize alg)))

genParityPubKey :: Gen ParityPubKey
genParityPubKey = ParityPubKey <$> genPubKey

genXOnlyPubKey :: Gen XOnlyPubKey
genXOnlyPubKey = XOnlyPubKey <$> genPubKey

genPubKey :: Gen PubKeyXY
genPubKey = derivePubKey <$> genSecKey

genSecKey :: Gen SecKey
genSecKey = Gen.just $ importSecKey <$> Gen.bytes (Range.singleton 32)

genOutPoint :: Gen OutPoint
genOutPoint =
  OutPoint
    <$> genTxHash
    <*> Gen.word32 Range.linearBounded

genBlockHeader :: Gen BlockHeader
genBlockHeader =
  BlockHeader
    <$> Gen.word32 Range.linearBounded
    <*> genBlockHash
    <*> genHash256
    <*> Gen.word32 Range.linearBounded
    <*> Gen.word32 Range.linearBounded
    <*> Gen.word32 Range.linearBounded

genTx :: Gen Tx
genTx = Gen.choice [genLegacyTx, genWitnessTx]

genLegacyTx :: Gen Tx
genLegacyTx =
  Tx
    <$> Gen.word32 Range.linearBounded
    <*> Gen.list (Range.linear 1 10) genTxIn
    <*> Gen.list (Range.linear 1 10) genTxOut
    <*> pure []
    <*> Gen.word32 Range.linearBounded

genWitnessTx :: Gen Tx
genWitnessTx = do
  numInputs <- Gen.int $ Range.linear 1 10
  Tx
    <$> Gen.word32 Range.linearBounded
    <*> replicateM numInputs genTxIn
    <*> Gen.list (Range.linear 1 10) genTxOut
    <*> replicateM numInputs (Gen.filter (not . null) genWitnessStack)
    <*> Gen.word32 Range.linearBounded

genTxIn :: Gen TxIn
genTxIn =
  TxIn
    <$> genOutPoint
    <*> Gen.bytes (Range.linear 0 100)
    <*> Gen.word32 Range.linearBounded

genTxOut :: Gen TxOut
genTxOut =
  TxOut
    <$> Gen.word64 Range.linearBounded
    <*> Gen.bytes (Range.linear 0 100)

genBlockHash :: Gen BlockHash
genBlockHash = BlockHash <$> genHash256

genWitnessData :: Gen WitnessData
genWitnessData = Gen.list (Range.linear 0 10) (Gen.filter (not . null) genWitnessStack)

genWitnessStack :: Gen WitnessStack
genWitnessStack = Gen.list (Range.linear 0 10) genWitnessStackItem

genWitnessStackItem :: Gen WitnessStackItem
genWitnessStackItem = Gen.bytes (Range.linear 0 32)

genTxHash :: Gen TxHash
genTxHash = TxHash <$> genHash256

genHash256 :: Gen Hash256
genHash256 = sha256 <$> Gen.bytes (Range.singleton 256)

genTaroNetwork :: Gen Network
genTaroNetwork = Gen.choice [pure btc, pure btcTest, pure btcRegTest]

genLazyBytes :: Range Int -> Gen BSL.ByteString
genLazyBytes range = BSL.fromStrict <$> Gen.bytes range
