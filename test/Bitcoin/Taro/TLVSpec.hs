{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Bitcoin.Taro.TLVSpec where

import Bitcoin.Taro.TLV
import Bitcoin.Taro.TestUtils
import Bitcoin.Util (decodeHexLazy)
import Control.Monad (forM_)
import Data.Aeson (FromJSON)
import qualified Data.Aeson as JSON
import Data.Binary (decodeOrFail, encode)
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Sequence as Seq
import qualified Data.Set as Set
import qualified Data.Text.Lazy as Text
import Data.Word (Word64)
import GHC.Generics (Generic)
import Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Paths_bitcoin_taro
import Test.Hspec
import Test.Tasty

test_Stream_encodeDecodeInverse :: TestTree
test_Stream_encodeDecodeInverse = encodeDecodeInverse genStream

test_Record_encodeDecodeInverse :: TestTree
test_Record_encodeDecodeInverse = encodeDecodeInverse genRecord

test_BigSize_encodeDecodeInverse :: TestTree
test_BigSize_encodeDecodeInverse = encodeDecodeInverse genBigSize

genStream :: Gen Stream
genStream = do
  types <- Set.toAscList <$> Gen.set (Range.linear 0 10) genType
  records <- Gen.list (Range.linear 0 10) genRecord
  pure $ Stream $ Seq.fromList $ (\(ty, r) -> r {recordType = ty}) <$> zip types records

genRecord :: Gen Record
genRecord = do
  size <- Gen.integral (Range.linear 1 1024)
  Record
    <$> genType
    <*> pure (BigSize size)
    <*> (BSL.fromStrict <$> Gen.bytes (Range.singleton (fromIntegral size)))

genType :: Gen Type
genType = Type <$> Gen.word64 Range.linearBounded

genBigSize :: Gen BigSize
genBigSize = BigSize <$> Gen.word64 Range.linearBounded

data BigSizeDecodingVector = BigSizeDecodingVector
  { name :: String,
    value :: Word64,
    bytes :: String,
    exp_error :: Maybe String
  }
  deriving (Generic, FromJSON)

data BigSizeEncodingVector = BigSizeEncodingVector
  { name :: String,
    value :: Word64,
    bytes :: String
  }
  deriving (Generic, FromJSON)

spec_BigSize :: Spec
spec_BigSize = describe "BigSize test vectors" $ do
  decodingVectors <- runIO $ do
    testVectorFile <- getDataFileName "test/vectors/BigSize.decoding.json"
    Just (vectors :: [BigSizeDecodingVector]) <- JSON.decodeFileStrict testVectorFile
    return vectors
  forM_ decodingVectors $ \case
    BigSizeDecodingVector {name, value, bytes, exp_error}
      | Nothing <- exp_error ->
        it ("should decode [" <> name <> "]") $ do
          Just input <- pure $ decodeHexLazy (Text.pack bytes)
          decodeOrFail input `shouldBe` Right (mempty, BSL.length input, BigSize value)
      | otherwise ->
        it ("should fail to decode [" <> name <> "]") $ do
          Just input <- pure $ decodeHexLazy (Text.pack bytes)
          decodeOrFail input `shouldNotBe` Right (mempty, BSL.length input, BigSize value)
  encodingVectors <- runIO $ do
    testVectorFile <- getDataFileName "test/vectors/BigSize.encoding.json"
    Just (vectors :: [BigSizeEncodingVector]) <- JSON.decodeFileStrict testVectorFile
    return vectors
  forM_ encodingVectors $ \case
    BigSizeEncodingVector {name, value, bytes} -> do
      it ("should encode [" <> name <> "]") $ do
        Just expectedEncodedValue <- pure $ decodeHexLazy (Text.pack bytes)
        encode (BigSize value) `shouldBe` expectedEncodedValue
