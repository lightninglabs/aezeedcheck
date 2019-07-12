package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightningnetwork/lnd/aezeed"
	"github.com/lightningnetwork/lnd/keychain"
)

var (
	// mnemonic is the user's aezeed paas phrase in full.
	mnemonic = flag.String("mnemonic", "", "your aezeed mnemonic with "+
		"each word separated by a new line")

	// aezeedPass is an optional passphrase that may be required to
	// properly decrypt an aezeed if it was created with a passphrase.
	aezeedPass = flag.String("pass", "", "an optional password used to "+
		"encrypt the aezeed pass phrase")
)

// deriveFirstKey...
func deriveFirstKey(rootKey *hdkeychain.ExtendedKey, purpose uint32,
	keyFamily keychain.KeyFamily) (*btcec.PublicKey, error) {

	accountKey, err := deriveAccountKey(rootKey, purpose, keyFamily)
	if err != nil {
		return nil, err
	}

	externalBranch, err := accountKey.Child(0)
	if err != nil {
		return nil, err
	}

	firstChild, err := externalBranch.Child(0)
	if err != nil {
		return nil, err
	}

	return firstChild.ECPubKey()
}

// deriveAccountKey...
func deriveAccountKey(rootKey *hdkeychain.ExtendedKey,
	purpose uint32,
	keyFamily keychain.KeyFamily) (*hdkeychain.ExtendedKey, error) {

	purposeKey, err := rootKey.Child(
		purpose + hdkeychain.HardenedKeyStart,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to derive purpose key; %v", err)
	}
	coinTypeKey, err := purposeKey.Child(
		keychain.CoinTypeBitcoin + hdkeychain.HardenedKeyStart,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to generate coin type key: %v", err)
	}
	accountKey, err := coinTypeKey.Child(
		uint32(keyFamily) + hdkeychain.HardenedKeyStart,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to derive account key: %v", err)
	}

	return accountKey, nil
}

func keyToP2wkhAddr(key *btcec.PublicKey) (btcutil.Address, error) {
	pubKeyHash := btcutil.Hash160(key.SerializeCompressed())

	return btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
}

func keyToNp2wkhAddr(key *btcec.PublicKey) (btcutil.Address, error) {
	pubKeyHash := btcutil.Hash160(key.SerializeCompressed())

	// First, we'll generate a normal p2wkh address from the pubkey hash.
	witAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		pubKeyHash, &chaincfg.MainNetParams,
	)
	if err != nil {
		return nil, err
	}

	// Next we'll generate the witness program which can be used as a
	// pkScript to pay to this generated address.
	witnessProgram, err := txscript.PayToAddrScript(witAddr)
	if err != nil {
		return nil, err
	}

	// Finally, we'll use the witness program itself as the pre-image to a
	// p2sh address. In order to spend, we first use the witnessProgram as
	// the sigScript, then present the proper <sig, pubkey> pair as the
	// witness.
	return btcutil.NewAddressScriptHash(
		witnessProgram, &chaincfg.MainNetParams,
	)
}

func main() {
	flag.Parse()

	if *mnemonic == "" {
		flag.PrintDefaults()
		return
	}

	mnemonicPhrase := strings.Split(*mnemonic, " ")
	if len(mnemonicPhrase) != aezeed.NummnemonicWords {
		log.Fatalf("expected %v words, instead got %v",
			aezeed.NummnemonicWords, len(mnemonicPhrase))
	}

	var aezeedPhrase aezeed.Mnemonic
	copy(aezeedPhrase[:], mnemonicPhrase)

	var password []byte
	if *aezeedPass != "" {
		password = []byte(*aezeedPass)
	}

	cipherSeed, err := aezeedPhrase.ToCipherSeed(password)
	if err != nil {
		log.Fatalf("unable to decrypt cipher seed: %v", err)
	}

	fmt.Printf("Wallet Birthday: %v, Internal Version: %v\n",
		cipherSeed.BirthdayTime(), cipherSeed.InternalVersion)

	entropy := cipherSeed.Entropy

	rootKey, err := hdkeychain.NewMaster(
		entropy[:], &chaincfg.MainNetParams,
	)
	if err != nil {
		log.Fatalf("unable to make HD priv root: %v", err)
	}

	nodePub, err := deriveFirstKey(
		rootKey, keychain.BIP0043Purpose, keychain.KeyFamilyNodeKey,
	)
	if err != nil {
		log.Fatalf("unable to derive node key: %v", err)
	}

	firstP2wkhKey, err := deriveFirstKey(
		rootKey, waddrmgr.KeyScopeBIP0084.Purpose, 0,
	)
	if err != nil {
		log.Fatalf("unable to derive first segwit addr: %v", err)
	}
	firstSegwitAddr, err := keyToP2wkhAddr(firstP2wkhKey)
	if err != nil {
		log.Fatalf("unable to create p2wkh addr: %v", err)
	}

	firstNp2wkhKey, err := deriveFirstKey(
		rootKey, waddrmgr.KeyScopeBIP0049Plus.Purpose, 0,
	)
	if err != nil {
		log.Fatalf("unable to derive first nested segwit addr: %v", err)
	}
	firstNestedSegwitAddr, err := keyToNp2wkhAddr(firstNp2wkhKey)
	if err != nil {
		log.Fatalf("unable to create np2wkh addr: %v", err)
	}

	fmt.Println("Node pub key: ", hex.EncodeToString(nodePub.SerializeCompressed()))

	fmt.Println("First p2wkh address: ", firstSegwitAddr)
	fmt.Println("First n2pwkh address", firstNestedSegwitAddr)
}
