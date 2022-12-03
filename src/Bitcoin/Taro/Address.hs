{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Bitcoin.Taro.Address
  ( mainnetHrp,
    testnetHrp,
    regTestHrp,
    sigNetHrp,
    simNetHrp,
    deriveHrp,
    Address (..),
    knownAddressPayloadTypes,
    addressToBech32,
    bech32ToAddress,
  )
where

import Bitcoin (Network, PubKeyXY, btc, btcRegTest, btcTest)
import Bitcoin.Address.Bech32
import Bitcoin.Taro.Asset (AssetKeyFamily, Genesis, TaroVersion)
import Bitcoin.Taro.TLV (TLV)
import qualified Bitcoin.Taro.TLV as TLV
import Bitcoin.Taro.Util (ParityPubKey (..))
import Bitcoin.Util (eitherToMaybe)
import Control.Applicative (optional)
import Control.Monad (guard)
import Data.Binary (Binary, decodeOrFail, encode)
import qualified Data.ByteString.Lazy as BSL
import Data.Functor ((<&>))
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Word (Word64)
import GHC.Generics (Generic)

-- | The human readable part for mainnet Taro addresses.
mainnetHrp :: HRP
mainnetHrp = "taro"

-- | The human readable part for testnet Taro addresses.
testnetHrp :: HRP
testnetHrp = "tarot"

-- | The human readable part for regtest Taro addresses.
regTestHrp :: HRP
regTestHrp = "tarort"

-- | The human readable part for signet Taro addresses.
sigNetHrp :: HRP
sigNetHrp = "tarotb"

-- | The human readable part for simnet Taro addresses.
simNetHrp :: HRP
simNetHrp = "tarosb"

-- TODO: Move to taro network wrapper type.

-- | Derive the 'HRP' of a Taro address from a 'Network'.
deriveHrp :: Network -> Maybe HRP
deriveHrp net
  | net == btc = Just mainnetHrp
  | net == btcTest = Just testnetHrp
  | net == btcRegTest = Just regTestHrp
  | otherwise = Nothing

-- | A taro address describes a single-asset Taro send.
data Address = Address
  { taroVersion :: TaroVersion,
    assetGenesis :: Genesis,
    assetKeyFamily :: Maybe AssetKeyFamily,
    assetScriptKey :: PubKeyXY,
    internalKey :: PubKeyXY,
    amount :: Word64
  }
  deriving (Generic, Show, Eq)
  deriving (Binary) via (TLV Address)

instance TLV.ToStream Address where
  toStream Address {..} =
    mempty
      `TLV.addRecord` (taroVersion `TLV.ofType` taroVersionTLV)
      `TLV.addRecord` (assetGenesis `TLV.ofDynamicType` assetGenesisTLV)
      `TLV.addRecords` (assetKeyFamily <&> (`TLV.ofType` assetKeyFamilyTLV))
      `TLV.addRecord` (ParityPubKey assetScriptKey `TLV.ofType` assetScriptKeyTLV)
      `TLV.addRecord` (ParityPubKey internalKey `TLV.ofType` internalKeyTLV)
      `TLV.addRecord` (TLV.BigSize amount `TLV.ofDynamicType` amountTLV)

instance TLV.FromStream Address where
  fromStream stream = do
    m <- TLV.streamToMap stream
    Address
      <$> m
      `TLV.getValue` taroVersionTLV
      <*> m
      `TLV.getValue` assetGenesisTLV
      <*> optional (m `TLV.getValue` assetKeyFamilyTLV)
      <*> (unParityPubKey <$> m `TLV.getValue` assetScriptKeyTLV)
      <*> (unParityPubKey <$> m `TLV.getValue` internalKeyTLV)
      <*> (TLV.unBigSize <$> m `TLV.getValue` amountTLV)

knownAddressPayloadTypes :: Set TLV.Type
knownAddressPayloadTypes =
  Set.fromAscList
    [ taroVersionTLV,
      assetGenesisTLV,
      assetKeyFamilyTLV,
      assetScriptKeyTLV,
      internalKeyTLV,
      amountTLV
    ]

taroVersionTLV, assetGenesisTLV, assetKeyFamilyTLV, assetScriptKeyTLV, internalKeyTLV, amountTLV :: TLV.Type
taroVersionTLV = 0
assetGenesisTLV = 2
assetKeyFamilyTLV = 3
assetScriptKeyTLV = 4
internalKeyTLV = 6
amountTLV = 8

-- | Convert a Taro address to a human-readable string in 'Bech32m' encoding for
-- a given network. This will fail if the network is invalid or unknown. No
-- character length limit is applied to the output.
addressToBech32 :: Network -> Address -> Maybe Bech32
addressToBech32 net address = do
  hrp <- deriveHrp net
  let bytes = BSL.unpack $ encode address
  Bech32EncodeResult {encodeResult, encodeValidHrp = True} <- pure $ bech32EncodeResult Bech32m hrp (toBase32 bytes)
  return encodeResult

-- | Convert a human-readable string in 'Bech32m' encoding to a Taro address for
-- a given network. This will fail if the network is invalid or unknown or if
-- the input is not Bech32 encoded. No character length limit is applied to the
-- input.
bech32ToAddress :: Network -> Bech32 -> Maybe Address
bech32ToAddress net text = do
  expectedHrp <- deriveHrp net
  Bech32DecodeResult
    { decodeResult = Just base32,
      decodeValidHrp = Just hrp,
      decodeValidChecksum = Just Bech32m,
      decodeValidCase = True,
      decodeValidDataLength = True
    } <-
    pure $ bech32DecodeResult text
  guard $ hrp == expectedHrp
  bytes <- BSL.pack <$> toBase256 base32
  ("", _, address) <- eitherToMaybe $ decodeOrFail bytes
  return address
