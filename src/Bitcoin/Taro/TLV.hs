{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}

module Bitcoin.Taro.TLV where

import Basement.IntegralConv (IntegralUpsize (integralUpsize), integralDownsize)
import Bitcoin (OutPoint, XOnlyPubKey)
import Bitcoin.Block (BlockHeader)
import Bitcoin.Taro.Util (HexString (..), ParityPubKey, bitsBytes)
import Control.Applicative (many)
import Control.Monad (foldM, replicateM)
import Data.Binary (Binary (get, put), Get, Put, decode, encode)
import Data.Binary.Get (getLazyByteString)
import qualified Data.Binary.Get as Bin
import Data.Binary.Put (putLazyByteString)
import qualified Data.ByteString.Lazy as BSL
import Data.Foldable (toList, traverse_)
import Data.List (genericLength)
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import Data.Word (Word16, Word32, Word64, Word8)
import GHC.Generics (Generic)

class FromStream a where
  fromStream :: Stream -> Maybe a

class ToStream a where
  toStream :: a -> Stream

class StaticSize a where
  staticSize :: BigSize

instance StaticSize Bool where
  staticSize = 1

instance StaticSize Word8 where
  staticSize = bitsBytes @Word8

instance StaticSize Word16 where
  staticSize = bitsBytes @Word16

instance StaticSize Word32 where
  staticSize = bitsBytes @Word32

instance StaticSize Word64 where
  staticSize = bitsBytes @Word64

instance StaticSize XOnlyPubKey where
  staticSize = 32

instance StaticSize ParityPubKey where
  staticSize = 33

instance StaticSize OutPoint where
  staticSize = 36

instance StaticSize BlockHeader where
  staticSize = 80

-- | A utility newtype wrapper for types with a TLV encoding.
newtype TLV a = TLV
  { unTLV :: a
  }

instance (ToStream a, FromStream a) => Binary (TLV a) where
  put = putStream . unTLV
  get = TLV <$> getStream

putStream :: ToStream a => a -> Put
putStream = put . toStream

getStream :: FromStream a => Get a
getStream =
  get
    >>= ( \case
            Just x -> return x
            Nothing -> fail "could not decode TLV stream"
        )
      . fromStream

-- | Utility newtype for encoding nested TLV streams a length prefix.
newtype LengthPrefix n a = LengthPrefix
  { unLengthPrefix :: [a]
  }

instance (Integral n, Binary n, Binary a) => Binary (LengthPrefix n a) where
  put (LengthPrefix xs) = do
    put @n $ genericLength xs
    traverse_ (put . VarBytes) xs
  get = do
    n <- get @n
    LengthPrefix <$> replicateM (fromIntegral n) (unVarBytes <$> get)

-- | Utility newtype for encoding nested TLV records with a length prefix.
newtype VarBytes a = VarBytes
  { unVarBytes :: a
  }

instance Binary a => Binary (VarBytes a) where
  put (VarBytes x) = do
    let bytes = encode x
    put @BigSize $ fromIntegral $ BSL.length bytes
    putLazyByteString bytes
  get = do
    n <- get @BigSize
    VarBytes <$> Bin.isolate (fromIntegral n) get

-- | Utility newtype for encoding ByteStrings as is with a length prefix.
newtype Bytes = Bytes
  { unBytes :: BSL.ByteString
  }

instance Binary Bytes where
  put (Bytes bytes) = do
    put @BigSize $ fromIntegral $ BSL.length bytes
    putLazyByteString bytes
  get = do
    n <- get @BigSize
    Bytes <$> getLazyByteString (fromIntegral n)

newtype Stream = Stream (Seq Record)
  deriving (Generic, Show, Eq, Semigroup, Monoid)

instance Binary Stream where
  put (Stream xs) = traverse_ put xs
  get = Stream . Seq.fromList <$> many get

addRecord :: Stream -> Record -> Stream
addRecord (Stream rs) r = Stream (rs Seq.|> r)

addRecords :: Foldable t => Stream -> t Record -> Stream
addRecords s t = s <> Stream (Seq.fromList $ toList t)

type Record = Record' BSL.ByteString

data Record' v = Record
  { recordType :: Type,
    recordLength :: BigSize,
    recordValue :: v
  }
  deriving (Generic, Eq, Functor)

newtype PlainString = PlainString String

instance Show PlainString where
  show (PlainString s) = s

deriving instance Show (Record' PlainString)

instance Show Record where
  showsPrec n r = showsPrec n (PlainString . ("fromJust $ decodeHexLazy " <>) . show . HexString <$> r)

instance Binary Record where
  get = do
    recordType <- get
    recordLength <- get
    recordValue <- getLazyByteString $ fromIntegral recordLength
    pure Record {..}
  put Record {..} = do
    put recordType
    put recordLength
    putLazyByteString recordValue

data StaticValue = StaticValue
  { recordLength :: BigSize,
    recordValue :: BSL.ByteString
  }

newtype Type = Type Word64
  deriving (Generic, Show, Eq, Ord)
  deriving newtype (Num, Enum, Bounded, Real, Integral)
  deriving (Binary) via BigSize

newtype BigSize = BigSize
  { unBigSize :: Word64
  }
  deriving (Generic, Show, Eq, Ord)
  deriving newtype (Num, Enum, Real, Integral)

instance Binary BigSize where
  put (BigSize x)
    | x < 0xfd =
        put (integralDownsize x :: Word8)
    | x < 0x10000 = do
        put (0xfd :: Word8)
        put (integralDownsize x :: Word16)
    | x < 0x100000000 = do
        put (0xfe :: Word8)
        put (integralDownsize x :: Word32)
    | otherwise = do
        put (0xff :: Word8)
        put x
  get =
    BigSize <$> do
      get @Word8 >>= \case
        tag | tag < 0xfd -> pure $ integralUpsize tag
        0xfd -> integralUpsize <$> get @Word16
        0xfe -> integralUpsize <$> get @Word32
        _ -> get @Word64

ofDynamicType :: Binary a => a -> Type -> Record
x `ofDynamicType` t =
  let recordValue = encode x
   in Record
        { recordType = t,
          recordLength = fromIntegral $ BSL.length recordValue,
          recordValue
        }

ofLength :: Binary a => a -> BigSize -> StaticValue
x `ofLength` recordLength =
  StaticValue
    { recordValue = encode x,
      recordLength
    }

ofType :: forall a. (Binary a, StaticSize a) => a -> Type -> Record
x `ofType` recordType =
  let recordValue = encode x
   in Record
        { recordType,
          recordLength = staticSize @a,
          recordValue
        }

ofByteString :: BSL.ByteString -> Type -> Record
recordValue `ofByteString` t =
  Record
    { recordType = t,
      recordLength = fromIntegral $ BSL.length recordValue,
      recordValue
    }

mapToStream :: Map Type BSL.ByteString -> Stream
mapToStream m =
  Stream $ Seq.fromList $ uncurry (flip ofByteString) <$> Map.toAscList m

streamToMap :: Stream -> Maybe (Map Type BSL.ByteString)
streamToMap (Stream s) =
  Map.fromDescList . snd
    <$> foldM
      ( \(minType, m) -> \case
          (Record t _ v)
            | minType <= t -> pure (t + 1, (t, v) : m)
            | otherwise -> Nothing
      )
      (0, [])
      s

getValue :: Binary a => Map Type BSL.ByteString -> Type -> Maybe a
m `getValue` t = decode <$> t `Map.lookup` m

getByteString :: Map Type BSL.ByteString -> Type -> Maybe BSL.ByteString
m `getByteString` t = t `Map.lookup` m
