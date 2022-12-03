{-# LANGUAGE OverloadedStrings #-}

module Bitcoin.Taro.AddressSpec where

import Bitcoin (XOnlyPubKey (..))
import Bitcoin.Constants
import Bitcoin.Taro.Address
import qualified Bitcoin.Taro.Asset as Asset
import qualified Bitcoin.Taro.AssetSpec as Asset
import Bitcoin.Taro.TestUtils
import Bitcoin.Util (decodeHexLazy, encodeHexLazy)
import Data.Binary (decode, encode)
import Data.Maybe (fromJust)
import Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.Hedgehog

test_Human_Readable_Part :: TestTree
test_Human_Readable_Part =
    testGroup
        "hrp"
        [ testCase "mainnet" $ mainnetHrp @?= "taro"
        , testCase "testnet" $ testnetHrp @?= "tarot"
        , testCase "regtest" $ regTestHrp @?= "tarort"
        , testCase "signet" $ sigNetHrp @?= "tarotb"
        , testCase "simnet" $ simNetHrp @?= "tarosb"
        ]

test_deriveHrp :: TestTree
test_deriveHrp =
    testGroup
        "deriveHrp"
        [ testCase "mainnet" $ deriveHrp btc @?= Just mainnetHrp
        , testCase "testnet" $ deriveHrp btcTest @?= Just testnetHrp
        , testCase "regtest" $ deriveHrp btcRegTest @?= Just regTestHrp
        , testCase "unknown" $ deriveHrp btc{getMaxSatoshi = 0} @?= Nothing
        ]

test_Address_encodeDecodeInverse :: TestTree
test_Address_encodeDecodeInverse =
    encodeDecodeInverse genAddress

genAddress :: Gen Address
genAddress =
    Address
        <$> Asset.genTaroVersion
        <*> Asset.genGenesis
        <*> Gen.maybe Asset.genAssetKeyFamily
        <*> genPubKey
        <*> genPubKey
        <*> Gen.word64 Range.linearBounded

test_Address_fromToTextInverse :: TestTree
test_Address_fromToTextInverse =
    testPropertyNamed
        "forall (x :: Address, net :: Network) . (bech32ToAddress net =<< addressToBech32 net x) == Just x"
        "prop_addressToBech32_bech32ToAddress_inverse"
        $ withTests 100
        $ property
        $ do
            network <- forAll genTaroNetwork
            address <- forAll genAddress
            ( do
                    text <- addressToBech32 network address
                    bech32ToAddress network text
                )
                === Just address

test_Address_vectors :: TestTree
test_Address_vectors =
    testGroup
        "normal"
        [ testCase "encode" $
            encodeHexLazy (encode normalAddress) @?= expectedEncodingHex
        , testCase "decode" $
            decode <$> decodeHexLazy expectedEncodingHex @?= Just normalAddress
        ]
  where
    normalAddress :: Address
    normalAddress =
        Address
            { taroVersion = Asset.TaroV0
            , assetGenesis =
                decode $ fromJust $ decodeHexLazy "8fcb18f0c3ef438a5210cec0f3ec07c5454904114dd61eda9623af7ea14104e7a2b59f23243032666335383066616430663032316163356366653039336339323564356431623964611202fc580fad0f021ac5cfe093c925d5d1b9da4e20d0df00"
            , assetKeyFamily = Nothing
            , assetScriptKey = pubKey
            , internalKey = pubKey
            , amount = 7940090206634810467
            }
    expectedEncodingHex = "00010002618fcb18f0c3ef438a5210cec0f3ec07c5454904114dd61eda9623af7ea14104e7a2b59f23243032666335383066616430663032316163356366653039336339323564356431623964611202fc580fad0f021ac5cfe093c925d5d1b9da4e20d0df00042102a0afeb165f0ec36880b68e0baabd9ad9c62fd1a69aa998bc30e9a346202e078f062102a0afeb165f0ec36880b68e0baabd9ad9c62fd1a69aa998bc30e9a346202e078f0809ff6e30ddf97b069c63"
    pubKey = xOnlyPubKey $ decode $ fromJust $ decodeHexLazy "a0afeb165f0ec36880b68e0baabd9ad9c62fd1a69aa998bc30e9a346202e078f"
