{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Bitcoin.Taro.Util where

import Bitcoin
import Crypto.Hash (Digest, HashAlgorithm, digestFromByteString)
import Crypto.Hash.IO (HashAlgorithm (HashDigestSize))
import Data.Binary (Binary, Get, Put, get, put)
import Data.Binary.Get (getByteString, getRemainingLazyByteString)
import Data.Binary.Put (putByteString, putLazyByteString)
import Data.Bits (Bits (zeroBits), FiniteBits (finiteBitSize))
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Data.Data (Proxy (Proxy))
import Data.Maybe (fromJust)
import GHC.TypeLits (KnownNat, natVal)

bitsBytes :: forall a n. (FiniteBits a, Integral n) => n
bitsBytes = fromIntegral (finiteBitSize (zeroBits @a) `div` bytes)

bytes :: Integral a => a
bytes = 8

putDigest :: Digest alg -> Put
putDigest = putByteString . BA.convert

getDigest :: forall alg. (HashAlgorithm alg, KnownNat (HashDigestSize alg)) => Get (Digest alg)
getDigest = do
  Just digest <- digestFromByteString <$> getByteString (fromIntegral $ natVal $ Proxy @(HashDigestSize alg))
  return digest

zeroDigest :: forall alg. (HashAlgorithm alg, KnownNat (HashDigestSize alg)) => Digest alg
zeroDigest = fromJust $ digestFromByteString $ BS.pack $ replicate (fromIntegral $ natVal $ Proxy @(HashDigestSize alg)) 0

-- | Utility newtype for encoding pub keys with the parity byte
newtype ParityPubKey = ParityPubKey
  { unParityPubKey :: PubKey
  }

instance Binary ParityPubKey where
  put = putByteString . exportPubKey True . unParityPubKey
  get = do
    Just pubKey <- importPubKey <$> getByteString 33
    return $ ParityPubKey pubKey

newtype HexString a = HexString a

instance Show (HexString BSL.ByteString) where
  showsPrec n (HexString x) = showsPrec n (encodeHexLazy x)

-- | Utility newtype for encoding ByteStrings as is without a length prefix.
newtype RawBytes = RawBytes
  { unRawBytes :: BSL.ByteString
  }

instance Binary RawBytes where
  put (RawBytes b) = putLazyByteString b
  get = RawBytes <$> getRemainingLazyByteString
