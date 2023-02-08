package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"

	"crypto/sha256"
	"time"
  "math"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/daemon/client"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/daemon/pb"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/keys"
	"github.com/kaspanet/kaspad/domain/consensus/utils/constants"
	"github.com/kaspanet/kaspad/domain/consensus/utils/txscript"
	"github.com/kaspanet/kaspad/domain/dagconfig"
	"github.com/kaspanet/kaspad/util"

	"github.com/kaspanet/kaspad/cmd/kaspawallet/libkaspawallet"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/libkaspawallet/bip32"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/libkaspawallet/serialization"
	"github.com/kaspanet/kaspad/domain/consensus/model/externalapi"
	"github.com/kaspanet/kaspad/domain/consensus/utils/consensushashing"
	"github.com/kaspanet/kaspad/domain/consensus/utils/subnetworks"
	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
  "github.com/kaspanet/kaspad/domain/consensus/utils/utxo"
  "golang.org/x/crypto/blake2b"
  "github.com/kaspanet/kaspad/infrastructure/network/rpcclient"
  "github.com/kaspanet/kaspad/app/appmessage"

)

//var dagParams = &dagconfig.MainnetParams

var dagParams = &dagconfig.DevnetParams
var walletpath = "/home/pieroforfora/.kaspawallet/kaspa-devnet/keys.json"
const secretSize = 32 

var feePerInput = uint64(30000)

var locktime = uint64(time.Now().Add(10 * time.Second).Unix()*1000)

// var amount = uint64(1)
var amountInSompi = uint64(1000000)
func main() {
	flag.Parse()

	daemonClient, tearDown, err := client.Connect("localhost:8082")
	if err != nil {
		fmt.Println("error:")
		fmt.Println(err)
	}
	defer tearDown()
	ctx, cancel := context.WithTimeout(context.Background(), (10 * time.Minute))
	defer cancel()

	keysFile, _ := keys.ReadKeysFile(dagParams, walletpath)

	password := "pieroforfora" //keys.GetPassword("Password:")
	mnemonics, _ := keysFile.DecryptMnemonics(password)

	reciptAddressz, _ := daemonClient.NewAddress(ctx, &pb.NewAddressRequest{})
	reciptAddress, _ := util.DecodeAddress(reciptAddressz.Address, dagParams.Prefix)
	_ = reciptAddress //Rimuovere
	fmt.Println("RECIPT ADDRESS:")
	fmt.Println(reciptAddressz.Address)
	fmt.Println("")

/*
  //COPYPASTEDTOREDEEM
txstr := "0aa001122a0a260a220a200b58e6fd1d838a29a13124101219dd67e8bc8ac4e669339c4b631e56a5780939100120011a2b08c0843d12250a23aa20a76285c58914e32b951c3c0009a4c414667d3cea38fcdf86d541f0bcb0a14f9c871a2d0890f9aea1ba0112240a22202d00d4596578229c4aa33e121d05451ea3ee308728496f2cbc6038a5352c41bdac2a160a14000000000000000000000000000000000000000012ef01122d0880e8eda1ba0112240a2220ea451d5a3da878dde675832ec3f56f17fe176e807b5bc27b8019f26646c10f65ac180122b4010a6f6b647562354172444b74364d72714e4c316847344164663976394e57335043684c576a4e507255444870787063533969745a583339664156653374464342726f6b654a5875664c4d6e5a5874624146596e4c635651576744537357755566786639534469796a4b3255446a755342661241c73b56584c2c9ef03437085c63e7382f5d16f1f1b432e62970bb61ded7b9934322b59d46de35a60843bd0d0982ca5e12da7bac69c87f0c81ddae8225561e2207012a056d2f302f31"
contractstr := "6382012088a820fa2688dd60f86a8afacf6f5d16fac82a7f9482a242a6680ee045f86f616bb08e8876aa204e340c03faaa70656252739cce36f2d9940c8b33f9f7fc1e47c5848c4646b5f467046fade163b076aa201aa0da2c632d8e31daa3ee33a6e827f0602412bcd4d9e1800f61219b0060b17f6888ac"
secret := "7cc86ae4683e6f36849ff3067610b15abee2c12cfc80aabd354509611091d156"
*/
/*
	txstr, contractstr, secret := initiateContract(reciptAddress.String(), mnemonics, daemonClient, ctx, keysFile)
	fmt.Println("TXSTR: ")
	fmt.Println(txstr)
	fmt.Println("")
	fmt.Println("CONTRACTSTR: ")
	fmt.Println(contractstr)
	fmt.Println("")
	fmt.Println("SECRET: ")
	fmt.Println(secret)
	fmt.Println("")
  fmt.Println("txstr := \""+txstr+"\"\ncontractstr := \""+contractstr+"\"\nsecret := \""+secret+"\"\n")
  fmt.Println("wait 20 seconds to let the cltv expire");
  time.Sleep(20 * time.Second)
*/

  //COPYPASTED TO REFUND I HAVE TO MINE SOME BLOCKS
txstr := "0aa001122a0a260a220a207882eabb417032a0d8877435e9f4ad4078f59a3e482068ade629f109388c84d3100120011a2b08c0843d12250a23aa20611052e5f213f66d67c9411b8b7475c452a10a789b463664c7ac1ed813f3e814871a2d0890f9aea1ba0112240a222057155fabccca3b3da41f40ebdcb4ce39cf001b07a0c6c564a7b4e61ff1e9ba66ac2a160a14000000000000000000000000000000000000000012ef01122d0880e8eda1ba0112240a2220b644f9854d909f6b436dcafcc6d698f36e6b20b9234acfe2a8852a8004197011ac180122b4010a6f6b64756235425a4c4e66545174533252374761463169344532396d79507747503365415076645a504337574a36353434467867673138723750656d764b455850427478376e72384848354d6a39704c32467861343457643331756a666631474e465076505877524a4c796b6d69646a12419fda452b60bb9da1bee0c725ce3927358d5ef7390ea5573876bca8dd5318cd180e48ca3c75658893bf4233ab611faebb3c760ff396ca5e2772e15f967464e7ef012a056d2f302f31"
contractstr := "6382012088a8207c184305c59e03402637387701efcfa1196b34ccba12f8136aad21db56baafde8876aa207aebb29e2971c171a05edfeac777accd6779d48ad0173252cbd3e69fe1c0dab66706b8205e328601b076aa207fdb8c8da8937a432f9f6d550492018f6ae5bc20227d9ea56240f2181b5623c16888ac"

//redmeemContract(contractstr, txstr, secret, mnemonics, daemonClient, ctx, keysFile)
refundContract(contractstr, txstr, mnemonics, daemonClient, ctx, keysFile)
}

func atomicSwapContract(pkhMe, pkhThem []byte, locktime uint64, secretHash []byte) ([]byte, error) {
	b := txscript.NewScriptBuilder()
  b.AddOp(txscript.OpIf) // Normal redeem path
  {
    // Require initiator's secret to be a known length that the redeeming
    // party can audit.  This is used to prevent fraud attacks between two
    // currencies that have different maximum data sizes.
    b.AddOp(txscript.OpSize)
    b.AddInt64(secretSize)
    b.AddOp(txscript.OpEqualVerify)

    // Require initiator's secret to be known to redeem the output.
    b.AddOp(txscript.OpSHA256)
    b.AddData(secretHash)
    b.AddOp(txscript.OpEqualVerify)
    
    // Verify their signature is being used to redeem the output.  This
    // would normally end with OP_EQUALVERIFY OP_CHECKSIG but this has been
    // moved outside of the branch to save a couple bytes.
    b.AddOp(txscript.OpDup)
    b.AddOp(txscript.OpBlake2b)
    b.AddData(pkhThem)
  }
  b.AddOp(txscript.OpElse) // Refund path
  {
    // Verify locktime and drop it off the stack (which is not done by
    // CLTV).
    b.AddLockTimeNumber(locktime)
    b.AddOp(txscript.OpCheckLockTimeVerify)
    //remove as SomeOne235 commit in txscripts extractAtomicSwapDataPushes
//    b.AddOp(txscript.OpDrop)
    // Verify our signature is being used to redeem the output.  This would
    // normally end with OP_EQUALVERIFY OP_CHECKSIG but this has been moved
    // outside of the branch to save a couple bytes.
    b.AddOp(txscript.OpDup)
    b.AddOp(txscript.OpBlake2b)
    b.AddData(pkhMe)
  }
  b.AddOp(txscript.OpEndIf)

  // Complete the signature check.
  b.AddOp(txscript.OpEqualVerify)
  b.AddOp(txscript.OpCheckSig)
  return b.Script()
}


func redeemP2SHContract(contract, sig, pubkey, secret []byte) ([]byte, error) {
	b := txscript.NewScriptBuilder()

	b.AddData(sig)
	b.AddData(pubkey)
	b.AddData(secret)
	b.AddInt64(1)
	b.AddData(contract)
	return b.Script()

}
func refundP2SHContract(contract, sig, pubkey []byte) ([]byte, error) {
  b := txscript.NewScriptBuilder()
  b.AddData(sig)
  b.AddData(pubkey)
  b.AddInt64(0)
  b.AddData(contract)
  return b.Script()
}


func sha256Hash(x []byte) []byte {
	h := sha256.Sum256(x)
	return h[:]
}
// Purpose and CoinType constants
const (
  SingleSignerPurpose = 44
  // Note: this is not entirely compatible to BIP 45 since
  // BIP 45 doesn't have a coin type in its derivation path.
  MultiSigPurpose = 45
  // TODO: Register the coin type in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
  CoinType = 111111
)

// Define Default path to calculate Extended key pair
func defaultPath(isMultisig bool) string {
  purpose := SingleSignerPurpose
  if isMultisig {
    purpose = MultiSigPurpose
  }

  return fmt.Sprintf("m/%d'/%d'/0'", purpose, CoinType)
}

func versionFromParams(params *dagconfig.Params) ([4]byte, error) {
	switch params.Name {
	case dagconfig.MainnetParams.Name:
		return bip32.KaspaMainnetPrivate, nil
	case dagconfig.TestnetParams.Name:
		return bip32.KaspaTestnetPrivate, nil
	case dagconfig.DevnetParams.Name:
		return bip32.KaspaDevnetPrivate, nil
	case dagconfig.SimnetParams.Name:
		return bip32.KaspaSimnetPrivate, nil
	}
	return [4]byte{}, errors.Errorf("unknown network %s", params.Name)
}

func getAddresses(daemonClient pb.KaspawalletdClient, ctx context.Context) []string {
	addressesResponse, err := daemonClient.ShowAddresses(ctx, &pb.ShowAddressesRequest{})
	if err != nil {
		log.Fatal(err)
		return []string{}
	}
	return addressesResponse.Address
}

func getAddressPath(addresses []string, address string, extendedPublicKeys []string, ecdsa bool) *string {
	for i, taddress := range addresses {
		if taddress == address {
			path := fmt.Sprintf("m/%d/%d", libkaspawallet.ExternalKeychain, i+1)
			new_address, _ := libkaspawallet.Address(dagParams, extendedPublicKeys, 1, path, ecdsa)
			if address == new_address.EncodeAddress() {
				return &path
			}
		}
	}
	return nil
}
func searchAddressByBlake2b(addresses []string, blake []byte, extendedPublicKeys []string, ecdsa bool) (*util.Address, *string) {
  for i := range addresses {
    path := fmt.Sprintf("m/%d/%d", libkaspawallet.ExternalKeychain, i+1)
    new_address, _ := libkaspawallet.Address(dagParams, extendedPublicKeys, 1, path, ecdsa)
    if hex.EncodeToString(getBlake2b(new_address.ScriptAddress())) == hex.EncodeToString(blake){
      return &new_address, &path
    }
  }
  return nil,nil
}

func isTransactionFullySigned(partiallySignedTransaction *serialization.PartiallySignedTransaction) bool {
	for _, input := range partiallySignedTransaction.PartiallySignedInputs {
		numSignatures := 0
		for _, pair := range input.PubKeySignaturePairs {
			if pair.Signature != nil {
				numSignatures++
			}
		}
		if uint32(numSignatures) < input.MinimumSignatures {
			return false
		}
	}
	return true
}
func rawTxInSignature(extendedKey *bip32.ExtendedKey, tx *externalapi.DomainTransaction, idx int, hashType consensushashing.SigHashType,
  sighashReusedValues *consensushashing.SighashReusedValues, ecdsa bool) ([]byte, error) {

  privateKey := extendedKey.PrivateKey()
  if ecdsa {
    return txscript.RawTxInSignatureECDSA(tx, idx, hashType, privateKey, sighashReusedValues)
  }

  schnorrKeyPair, err := privateKey.ToSchnorr()
  if err != nil {
    return nil, err
  }

  return txscript.RawTxInSignature(tx, idx, hashType, schnorrKeyPair, sighashReusedValues)
}
func extendedKeyFromMnemonicAndPath(mnemonic string, path string, params *dagconfig.Params) (*bip32.ExtendedKey, error) {
	seed := bip39.NewSeed(mnemonic, "")
	version, err := versionFromParams(params)
	if err != nil {
		return nil, err
	}
	master, err := bip32.NewMasterWithPath(seed, version, path)
	if err != nil {
		return nil, err
	}
	return master, nil
}

func printPartiallySignedTx(tx []byte) {
	partiallySignedTransaction, err := serialization.DeserializePartiallySignedTransaction(tx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Transaction HEX")
	fmt.Println(hex.EncodeToString(tx))

	fmt.Printf("Transaction ID: \t%s\n", consensushashing.TransactionID(partiallySignedTransaction.Tx))
	fmt.Println()

	allInputSompi := uint64(0)
	for index, input := range partiallySignedTransaction.Tx.Inputs {
		partiallySignedInput := partiallySignedTransaction.PartiallySignedInputs[index]

		fmt.Printf("Input %d: \tOutpoint: %s:%d \tAmount: %.2f Kaspa\n", index, input.PreviousOutpoint.TransactionID,
			input.PreviousOutpoint.Index, float64(partiallySignedInput.PrevOutput.Value)/float64(constants.SompiPerKaspa))
		fmt.Println(input.SignatureScript)

		allInputSompi += partiallySignedInput.PrevOutput.Value
	}

	allOutputSompi := uint64(0)
	for index, output := range partiallySignedTransaction.Tx.Outputs {
		scriptPublicKeyType, scriptPublicKeyAddress, err := txscript.ExtractScriptPubKeyAddress(output.ScriptPublicKey, dagParams)
		if err != nil {
			log.Fatal(err)
		}

		addressString := scriptPublicKeyAddress.EncodeAddress()
		if scriptPublicKeyType == txscript.NonStandardTy {
			scriptPublicKeyHex := hex.EncodeToString(output.ScriptPublicKey.Script)
			addressString = fmt.Sprintf("<Non-standard transaction script public key: %s>", scriptPublicKeyHex)
		}

		fmt.Printf("Output %d: \tRecipient: %s \tAmount: %.2f Kaspa\n",
			index, addressString, float64(output.Value)/float64(constants.SompiPerKaspa))

		allOutputSompi += output.Value
	}
	fmt.Println()

	fmt.Printf("Fee:\t%d Sompi\n", allInputSompi-allOutputSompi)
	fmt.Printf("GAS:\t%d Sompi\n", partiallySignedTransaction.Tx.Gas)

}

func getEmpty(extendedPublicKeys []string, derivationPath string) []*serialization.PubKeySignaturePair {
	fmt.Println("Into Empty:")
	emptyPubKeySignaturePairs := make([]*serialization.PubKeySignaturePair, len(extendedPublicKeys))
	for i, extendedPublicKey := range extendedPublicKeys {
		extendedKey, _ := bip32.DeserializeExtendedKey(extendedPublicKey)
		derivedKey, _ := extendedKey.DeriveFromPath(derivationPath)
		fmt.Println("keypair", derivedKey.String())
		fmt.Println("extended", extendedKey)
		emptyPubKeySignaturePairs[i] = &serialization.PubKeySignaturePair{
			ExtendedPublicKey: derivedKey.String(),
		}
	}
	return emptyPubKeySignaturePairs
}

func sendTransaction(client *rpcclient.RPCClient, rpcTransaction *appmessage.RPCTransaction) (string, error) {
  submitTransactionResponse, err := client.SubmitTransaction(rpcTransaction, true)
  if err != nil {
    return "", errors.Wrapf(err, "error submitting transaction")
  }
  return submitTransactionResponse.TransactionID, nil
}

func initiateContract(reciptAddress string, mnemonics []string, daemonClient pb.KaspawalletdClient, ctx context.Context, keysFile *keys.File) (string, string, string) {
	fmt.Println("Initiating Contract...")
	fmt.Println("")
	rand.Seed(time.Now().UnixNano())
	var secret [secretSize]byte


	rand.Read(secret[:])
	fmt.Println("SECRET: ")
	fmt.Println(hex.EncodeToString(secret[:]))
	fmt.Println("")

	secretHash := sha256Hash(secret[:])
	fmt.Println("SECRET HASH:")
	fmt.Println(hex.EncodeToString(secretHash))
	fmt.Println("")
	refundAddrs, _ := daemonClient.NewAddress(ctx, &pb.NewAddressRequest{})
	refundAddr, _ := util.DecodeAddress(refundAddrs.Address, dagParams.Prefix)
	fmt.Println("REFUND ADDR:")
	fmt.Println(refundAddr)
	fmt.Println("")
	changeAddrs, _ := daemonClient.NewAddress(ctx, &pb.NewAddressRequest{})
	changeAddr, _ := util.DecodeAddress(changeAddrs.Address, dagParams.Prefix)
	fmt.Println("CHANGE ADDR:")
	fmt.Println(changeAddr)
	fmt.Println("")
	reciptAddr, _ := util.DecodeAddress(reciptAddress, dagParams.Prefix)
	fmt.Println("RECIPT ADDR:")
	fmt.Println(reciptAddr)
	fmt.Println("")

  fmt.Println("BLAKE2BRECIPT",getBlake2b(reciptAddr.ScriptAddress()))
	contract, err := atomicSwapContract(getBlake2b(refundAddr.ScriptAddress()), getBlake2b(reciptAddr.ScriptAddress()),
		locktime, secretHash)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Contract:")
	fmt.Println(hex.EncodeToString(contract))
	fmt.Println("")

	contractP2SH, err := util.NewAddressScriptHash(contract, dagParams.Prefix)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ContractP2SH:")
	fmt.Println(contractP2SH)
	fmt.Println("")

	contractP2SHPkScript, err := txscript.PayToScriptHashScript(contract)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ContractP2SHPkScript:")
	fmt.Println(hex.EncodeToString(contractP2SHPkScript))
	fmt.Println("")

	//sendAmountSompi := uint64(amount * constants.SompiPerKaspa)
	sendAmountSompi := uint64(amountInSompi)

	addressesResponse, _ := daemonClient.ShowAddresses(ctx, &pb.ShowAddressesRequest{})

	input_amount := uint64(0)
	utxos := []*pb.UtxosByAddressesEntry{}
	inputs := []*externalapi.DomainTransactionInput{}
	partiallySignedInputs := []*serialization.PartiallySignedInput{}
	done := false

	for iaddr, address := range addressesResponse.Address {

		addr_utxos, _ := daemonClient.GetExternalSpendableUTXOs(ctx, &pb.GetExternalSpendableUTXOsRequest{Address: address})
		derivationPath := fmt.Sprintf("m/%d/%d", libkaspawallet.ExternalKeychain, iaddr+1)
		for _, utxo := range addr_utxos.Entries {
			if input_amount < (sendAmountSompi + feePerInput*uint64(len(utxos)+1)) {

				fmt.Println("utxo:")
				fmt.Println(utxo)
				fmt.Println("")
				utxos = append(utxos, utxo)
				emptyPubKeySignaturePairs := getEmpty(keysFile.ExtendedPublicKeys, derivationPath)

				txid, _ := externalapi.NewDomainTransactionIDFromString(utxo.Outpoint.TransactionId)
				inputs = append(inputs, &externalapi.DomainTransactionInput{PreviousOutpoint: externalapi.DomainOutpoint{
					TransactionID: *txid,
					Index:         utxo.Outpoint.Index,
				}})
				scriptPublicKey, _ := hex.DecodeString(utxo.UtxoEntry.ScriptPublicKey.ScriptPublicKey)
				partiallySignedInputs = append(partiallySignedInputs, &serialization.PartiallySignedInput{
					PrevOutput: &externalapi.DomainTransactionOutput{
						Value: utxo.UtxoEntry.Amount,
						ScriptPublicKey: &externalapi.ScriptPublicKey{
							Script:  scriptPublicKey,
							Version: uint16(utxo.UtxoEntry.ScriptPublicKey.Version),
						},
					},
					MinimumSignatures:  1,

					PubKeySignaturePairs: emptyPubKeySignaturePairs,
					DerivationPath:       derivationPath,
				})
				input_amount += utxo.UtxoEntry.Amount
			} else {
				done = true
				break
			}
		}
		if done {
			break
		}
	}

	fmt.Println("UTXOs:")
	fmt.Println(utxos)
	fmt.Println("")
	fmt.Println("INPUTS")
	fmt.Println(inputs)
	fmt.Println("")

	changeAddressScript, _ := txscript.PayToAddrScript(changeAddr)
	domainTransaction := &externalapi.DomainTransaction{
		Version: constants.MaxTransactionVersion,
		Inputs:  inputs,
		Outputs: []*externalapi.DomainTransactionOutput{
			{
				Value: sendAmountSompi,
				ScriptPublicKey: &externalapi.ScriptPublicKey{
					Version: constants.MaxScriptPublicKeyVersion,
					Script:  contractP2SHPkScript,
				},
			},
			{
				Value:           input_amount - sendAmountSompi - feePerInput*uint64(len(utxos)),
				ScriptPublicKey: changeAddressScript,
			},
		},
		LockTime:     0,
		SubnetworkID: subnetworks.SubnetworkIDNative,
		Gas:          0,
		Payload:      nil,
	}
	partiallySigned := &serialization.PartiallySignedTransaction{
		Tx:                    domainTransaction,
		PartiallySignedInputs: partiallySignedInputs,
	}
	ps, _ := serialization.SerializePartiallySignedTransaction(partiallySigned)
	signedTransaction, err := libkaspawallet.Sign(dagParams, mnemonics, ps, keysFile.ECDSA)
	if err != nil {
		log.Fatal(err)
	}

	signedTransactions := [][]byte{signedTransaction}

	fmt.Println("Signed Transaction:")
	fmt.Println(hex.EncodeToString(signedTransaction))

	response, err := daemonClient.Broadcast(ctx, &pb.BroadcastRequest{Transactions: signedTransactions})

	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	fmt.Println("Transactions were sent successfully!")
	fmt.Println("Transaction ID(s): ")
	for _, txID := range response.TxIDs {
		fmt.Printf("\t%s\n", txID)
	}
	return hex.EncodeToString(signedTransaction), hex.EncodeToString(contract), hex.EncodeToString(secret[:])

}

func getBlake2b(text []byte) ([]byte){
  hash := blake2b.Sum256(text)
  slice := hash[:]
  return slice
}
func dasmScript(script []byte)(string){
  plainScript,err := txscript.DisasmString(0, script)
  if err != nil {
    fmt.Println("impossible to dasm")
    log.Fatal(err)
  }
return plainScript
}

func printContract( description string, script []byte) {


	fmt.Println("")
  fmt.Println(description+":")
  fmt.Println(hex.EncodeToString(script))
  fmt.Println("DASM:")
  fmt.Println(dasmScript(script))
  fmt.Println("Blake2b:")
  fmt.Println(hex.EncodeToString(getBlake2b(script)))
	fmt.Println("")
}

func printRpcTransaction(rpcTransaction *appmessage.RPCTransaction){
  fmt.Println("Transaction:")
  fmt.Println("\tVersion:",rpcTransaction.Version)
  fmt.Println("\tLockTime:",rpcTransaction.LockTime)
  fmt.Println("\tSubnetworkID:",rpcTransaction.SubnetworkID)
  fmt.Println("\tGas:",rpcTransaction.Gas)
  fmt.Println("\tPayload:",rpcTransaction.Payload)
  fmt.Println("\tInputs:")
  for i := range rpcTransaction.Inputs{
    fmt.Println("\t\tInput:", i)
    fmt.Println("\t\tSignatureScript:",rpcTransaction.Inputs[i].SignatureScript)
    fmt.Println("\t\tSequence:",rpcTransaction.Inputs[i].Sequence)
    fmt.Println("\t\tSigOpCount:",rpcTransaction.Inputs[i].SigOpCount)
  }
  fmt.Println("Outputs:")
  for i := range rpcTransaction.Outputs{
    fmt.Println("\t\tOutput:",i)
    fmt.Println("\t\tAmount:",rpcTransaction.Outputs[i].Amount)
    fmt.Println("\t\tScriptPublicKey:")
    fmt.Println("\t\t\tVersion:",rpcTransaction.Outputs[i].ScriptPublicKey.Version)
    fmt.Println("\t\t\tScript:",rpcTransaction.Outputs[i].ScriptPublicKey.Script)
  }

}
func redeemContract(contractstr string, txstr string, secret string, mnemonics []string, daemonClient pb.KaspawalletdClient, ctx context.Context, keysFile *keys.File) {
	contractr, _ := hex.DecodeString(contractstr)
	secretr, _ := hex.DecodeString(secret)
	tx, _ := hex.DecodeString(txstr)
	printPartiallySignedTx(tx)
	transaction, _ := serialization.DeserializePartiallySignedTransaction(tx)
	txid := consensushashing.TransactionID(transaction.Tx)
	fmt.Println("Transaction ID:")
	fmt.Println(txid)
  fmt.Println("Secret:\n",secret)
	fmt.Println("")
	fmt.Println("**********************REDEEM*************************")
	fmt.Println("")
	addressesResponse, _ := daemonClient.ShowAddresses(ctx, &pb.ShowAddressesRequest{})
	addresses := addressesResponse.Address
	fmt.Println("Addresses:",len(addresses))
	//fmt.Println(addresses)
	fmt.Println("")


	pushes, err := txscript.ExtractAtomicSwapDataPushes(0, contractr)
	if err != nil {
		log.Fatal(err)
	}
	if pushes == nil {
		log.Fatal("contract is not an atomic swap script recognized by this tool")
	}

	recipientAddr, recipient_path := searchAddressByBlake2b(addresses,pushes.RecipientBlake2b[:],keysFile.ExtendedPublicKeys, keysFile.ECDSA)
	if err != nil {
		log.Fatal(err)
	}
  if recipientAddr == nil {
    log.Fatal("I don't know the key to redeem this contract")
  }
	fmt.Println("Pushes - Recipient from Contract:")
	fmt.Println(*recipientAddr, *recipient_path)
	fmt.Println("")

	refundAddr, refund_path := searchAddressByBlake2b(addresses,pushes.RefundBlake2b[:],keysFile.ExtendedPublicKeys, keysFile.ECDSA)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Pushes - Refund from Contract:")
	fmt.Println(*refundAddr,*refund_path)
	fmt.Println("")

	fmt.Println("Pushes - Secret hash from Contract:")
	fmt.Println(hex.EncodeToString(pushes.SecretHash[:]))
	fmt.Println("")

  //recipientAddr := reciptAddress
	contractHash, _ := util.NewAddressScriptHash(contractr, dagParams.Prefix)
	fmt.Println("contract hash:")
	fmt.Println(contractHash)
	fmt.Println("")


	fmt.Println("PATH:", recipient_path)

	//empty := getEmpty(keysFile.ExtendedPublicKeys, recipient_path)

  extendedKey, _ := extendedKeyFromMnemonicAndPath(mnemonics[0], defaultPath(false), dagParams)

	derivedKey, err := extendedKey.DeriveFromPath(*recipient_path)
  if err != nil { log.Fatal(err)}

  derivedPublicKey, err := derivedKey.Public()
  if err != nil { log.Fatal(err)}

	fmt.Println("")
	fmt.Println("Out of Empty:")
	fmt.Println("extended:\n", extendedKey)
	fmt.Println("keypair:\n", derivedKey.String())
  fmt.Println("derivedPublicKey:\n",derivedPublicKey.String())
//  fmt.Println("derivedPublicKeyiBlake2b:\n",getBlake2b(derivedPublicKey))

  publicKey,_ := derivedKey.PublicKey()

  var serializedPublicKey []byte
      serializedECDSAPublicKey, err := publicKey.Serialize()
      if err != nil {log.Fatal(err)}
      serializedPublicKey = serializedECDSAPublicKey[:]
      fmt.Println("publicKeyECDSA;\n", serializedPublicKey)
      fmt.Println("PublicKeyECDSA:",serializedPublicKey)
      fmt.Println("PublicKeyECDSABlake2b:\n",hex.EncodeToString(getBlake2b(serializedPublicKey)))
      schnorrPublicKey, err := publicKey.ToSchnorr()

      if err != nil {log.Fatal(err)}

      serializedSchnorrPublicKey, err := schnorrPublicKey.Serialize()
      if err != nil {log.Fatal(err)}
      serializedPublicKey = serializedSchnorrPublicKey[:]
      fmt.Println("serializedPublicKeyShnorr:\n",serializedPublicKey)
      fmt.Println("serializedPublicKeyiShonrrString:\n",hex.EncodeToString(serializedPublicKey))
      fmt.Println("serializedPublicKeyiShnorrBlake2b:\n",hex.EncodeToString(getBlake2b(serializedPublicKey)))

    if keysFile.ECDSA {
      serializedECDSAPublicKey, err := publicKey.Serialize()
      if err != nil {log.Fatal(err)}
      serializedPublicKey = serializedECDSAPublicKey[:]
      fmt.Println("publicKeyECDSA;\n", serializedPublicKey)
      fmt.Println("PublicKeyECDSA:",serializedPublicKey)
      fmt.Println("PublicKeyECDSABlake2b:\n",hex.EncodeToString(getBlake2b(serializedPublicKey)))

       } else {
      schnorrPublicKey, err := publicKey.ToSchnorr()

      if err != nil {log.Fatal(err)}

      serializedSchnorrPublicKey, err := schnorrPublicKey.Serialize()
      if err != nil {log.Fatal(err)}
      serializedPublicKey = serializedSchnorrPublicKey[:]
    }
  fmt.Println("serializedPublicKey:\n",serializedPublicKey)
  fmt.Println("serializedPublicKeyString:\n",hex.EncodeToString(serializedPublicKey))
  fmt.Println("serializedPublicKeyBlake2b:\n",hex.EncodeToString(getBlake2b(serializedPublicKey)))

  regenerated,_ := util.NewAddressPublicKey(serializedPublicKey[:], dagParams.Prefix)
  fmt.Println("regenerated address:\n",regenerated)

	script_pubkey, _ := txscript.PayToAddrScript(*recipientAddr)

	outputs := []*externalapi.DomainTransactionOutput{{
		//Value:           (transaction.Tx.Outputs[0].Value - uint64(feePerInput)*uint64(len(inputs))),
		Value:           (transaction.Tx.Outputs[0].Value - uint64(feePerInput)*uint64(1)),
		ScriptPublicKey: script_pubkey,
	}}

	fmt.Println("")
  fmt.Println("transaction.Tx.Outputs[0].ScriptPublicKey:\n", hex.EncodeToString(transaction.Tx.Outputs[0].ScriptPublicKey.Script))
	fmt.Println("")
  script_public_key,_ :=  txscript.NewScriptBuilder().AddOp(txscript.OpBlake2b).AddData(transaction.Tx.Outputs[0].ScriptPublicKey.Script).AddOp(txscript.OpEqual).Script()
  scp := &externalapi.ScriptPublicKey{
    Script: script_public_key,
    Version: constants.MaxScriptPublicKeyVersion,
  }

  scp =scp
  inputs := []*externalapi.DomainTransactionInput{{
    PreviousOutpoint: externalapi.DomainOutpoint{
      TransactionID: *txid,
      Index:         0,
    },
    SigOpCount: 1,
    //SignatureScript: contractr,
    //UTXOEntry: utxo.NewUTXOEntry(transaction.Tx.Outputs[0].Value,transaction.Tx.Outputs[0].ScriptPublicKey,false,0),
    UTXOEntry: utxo.NewUTXOEntry(transaction.Tx.Outputs[0].Value,transaction.Tx.Outputs[0].ScriptPublicKey,false,0),
  }}


	domainTransaction := &externalapi.DomainTransaction{
		Version: constants.MaxTransactionVersion,
		Outputs: outputs,
		Inputs: inputs,
		//LockTime: pushes.LockTime,
		LockTime:     0,
		SubnetworkID: subnetworks.SubnetworkIDNative,
		Gas:          0,
		Payload:      nil,
	}
  sighashReusedValues := &consensushashing.SighashReusedValues{}

	signature,_ := rawTxInSignature(derivedKey, domainTransaction, 0, consensushashing.SigHashAll, sighashReusedValues, keysFile.ECDSA)
	redeemSigScript, _ := redeemP2SHContract(contractr,  signature, serializedPublicKey, secretr)
	sigScript,_:= txscript.PayToScriptHashSignatureScript(redeemSigScript,nil)

  domainTransaction.Inputs[0].SignatureScript =   redeemSigScript

  fmt.Println("signature:\n",signature)
  fmt.Println("signatureString:\n",hex.EncodeToString(signature))
  fmt.Println("signatureBlake2b:\n",hex.EncodeToString(getBlake2b(signature)))


  printContract("Initial", contractr)


  printContract("Redeem", redeemSigScript)


  printContract("SigScript", sigScript)


  rpcTransaction := appmessage.DomainTransactionToRPCTransaction(domainTransaction)
  printRpcTransaction(rpcTransaction)
  fmt.Println("")
  kaspadClient, err := rpcclient.NewRPCClient("localhost:16610")

  if err != nil {
    fmt.Println("error:")
    fmt.Println(err)
  }
  txID,err :=sendTransaction(kaspadClient, rpcTransaction)
  if err != nil {
    log.Fatal(err)
  }
	fmt.Println("Transactions were sent successfully!")
	fmt.Println("Transaction ID(s): ")
  fmt.Printf("\t%s\n", txID)
}
func parsePushes(contractr []byte,addresses []string, keysFile *keys.File)(*util.Address, *string, *util.Address, *string, string, int64, uint64){
  pushes, err := txscript.ExtractAtomicSwapDataPushes(0, contractr)
  if err != nil {
    log.Fatal(err)
  }
  if pushes == nil {
    log.Fatal("contract is not an atomic swap script recognized by this tool")
  }

  recipientAddr, recipient_path := searchAddressByBlake2b(addresses,pushes.RecipientBlake2b[:],keysFile.ExtendedPublicKeys, keysFile.ECDSA)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("Pushes - Recipient from Contract:")
  fmt.Println(*recipientAddr, *recipient_path)
  fmt.Println("")

  refundAddr, refund_path := searchAddressByBlake2b(addresses,pushes.RefundBlake2b[:],keysFile.ExtendedPublicKeys, keysFile.ECDSA)
  if err != nil {
    log.Fatal(err)
  }

  if refundAddr == nil {
    log.Fatal("I don't know the key to refund this contract")
  }
  fmt.Println("Pushes - Refund from Contract:")
  fmt.Println(*refundAddr,*refund_path)
  fmt.Println("")

  fmt.Println("Pushes - Secret hash from Contract:")
  fmt.Println(hex.EncodeToString(pushes.SecretHash[:]))
  fmt.Println("")
  
  fmt.Println("Pushes - Secret size from Contract:")
  fmt.Println(pushes.SecretSize)
  fmt.Println("")

  fmt.Println("Pushes - LockTime from Contract:")
  fmt.Println(pushes.LockTime)
  fmt.Println("")
  return recipientAddr, recipient_path, refundAddr, refund_path, hex.EncodeToString(pushes.SecretHash[:]), pushes.SecretSize, pushes.LockTime

}
func refundContract(contractstr string, txstr string, mnemonics []string, daemonClient pb.KaspawalletdClient, ctx context.Context, keysFile *keys.File) {
	contractr, _ := hex.DecodeString(contractstr)
	tx, _ := hex.DecodeString(txstr)
	printPartiallySignedTx(tx)
	transaction, _ := serialization.DeserializePartiallySignedTransaction(tx)
	txid := consensushashing.TransactionID(transaction.Tx)
	fmt.Println("Transaction ID:")
	fmt.Println(txid)
	fmt.Println("")
	fmt.Println("**********************REFUND*************************")
	fmt.Println("")
	addressesResponse,  err := daemonClient.ShowAddresses(ctx, &pb.ShowAddressesRequest{})
  if err != nil{
  log.Fatal(err)
  }
	addresses := addressesResponse.Address
	fmt.Println("Addresses:",len(addresses))
	//fmt.Println(addresses)
	fmt.Println("")

  recipientAddr, recipient_path, refundAddr, refund_path, _, _, lockTime:= parsePushes(contractr, addresses,keysFile)
  //haCK TO B3 R3M0V3D
  lockTime=lockTime
	fmt.Println("PATH:", recipient_path)

//this is an hack to not refactor :-d
  recipientAddr,recipient_path = refundAddr, refund_path

	//empty := getEmpty(keysFile.ExtendedPublicKeys, recipient_path)

  extendedKey, _ := extendedKeyFromMnemonicAndPath(mnemonics[0], defaultPath(false), dagParams)

	derivedKey, err := extendedKey.DeriveFromPath(*recipient_path)
  if err != nil { log.Fatal(err)}

  derivedPublicKey, err := derivedKey.Public()
  if err != nil { log.Fatal(err)}

	fmt.Println("")
	fmt.Println("Out of Empty:")
	fmt.Println("extended:\n", extendedKey)
	fmt.Println("keypair:\n", derivedKey.String())
  fmt.Println("derivedPublicKey:\n",derivedPublicKey.String())
//  fmt.Println("derivedPublicKeyiBlake2b:\n",getBlake2b(derivedPublicKey))

  publicKey,_ := derivedKey.PublicKey()

  var serializedPublicKey []byte
      serializedECDSAPublicKey, err := publicKey.Serialize()
      if err != nil {log.Fatal(err)}
      serializedPublicKey = serializedECDSAPublicKey[:]
      fmt.Println("publicKeyECDSA;\n", serializedPublicKey)
      fmt.Println("PublicKeyECDSA:",serializedPublicKey)
      fmt.Println("PublicKeyECDSABlake2b:\n",hex.EncodeToString(getBlake2b(serializedPublicKey)))
      schnorrPublicKey, err := publicKey.ToSchnorr()

      if err != nil {log.Fatal(err)}

      serializedSchnorrPublicKey, err := schnorrPublicKey.Serialize()
      if err != nil {log.Fatal(err)}
      serializedPublicKey = serializedSchnorrPublicKey[:]
      fmt.Println("serializedPublicKeyShnorr:\n",serializedPublicKey)
      fmt.Println("serializedPublicKeyiShonrrString:\n",hex.EncodeToString(serializedPublicKey))
      fmt.Println("serializedPublicKeyiShnorrBlake2b:\n",hex.EncodeToString(getBlake2b(serializedPublicKey)))

    if keysFile.ECDSA {
      serializedECDSAPublicKey, err := publicKey.Serialize()
      if err != nil {log.Fatal(err)}
      serializedPublicKey = serializedECDSAPublicKey[:]
      fmt.Println("publicKeyECDSA;\n", serializedPublicKey)
      fmt.Println("PublicKeyECDSA:",serializedPublicKey)
      fmt.Println("PublicKeyECDSABlake2b:\n",hex.EncodeToString(getBlake2b(serializedPublicKey)))

       } else {
      schnorrPublicKey, err := publicKey.ToSchnorr()

      if err != nil {log.Fatal(err)}

      serializedSchnorrPublicKey, err := schnorrPublicKey.Serialize()
      if err != nil {log.Fatal(err)}
      serializedPublicKey = serializedSchnorrPublicKey[:]
    }
  fmt.Println("serializedPublicKey:\n",serializedPublicKey)
  fmt.Println("serializedPublicKeyString:\n",hex.EncodeToString(serializedPublicKey))
  fmt.Println("serializedPublicKeyBlake2b:\n",hex.EncodeToString(getBlake2b(serializedPublicKey)))

  regenerated,_ := util.NewAddressPublicKey(serializedPublicKey[:], dagParams.Prefix)
  fmt.Println("regenerated address:\n",regenerated)

	script_pubkey, _ := txscript.PayToAddrScript(*recipientAddr)

	outputs := []*externalapi.DomainTransactionOutput{{
		//Value:           (transaction.Tx.Outputs[0].Value - uint64(feePerInput)*uint64(len(inputs))),
		Value:           (transaction.Tx.Outputs[0].Value - uint64(feePerInput)*uint64(1)),
		ScriptPublicKey: script_pubkey,
	}}

	fmt.Println("")
  fmt.Println("transaction.Tx.Outputs[0].ScriptPublicKey:\n", hex.EncodeToString(transaction.Tx.Outputs[0].ScriptPublicKey.Script))
	fmt.Println("")
  script_public_key,_ :=  txscript.NewScriptBuilder().AddOp(txscript.OpBlake2b).AddData(transaction.Tx.Outputs[0].ScriptPublicKey.Script).AddOp(txscript.OpEqual).Script()
  scp := &externalapi.ScriptPublicKey{
    Script: script_public_key,
    Version: constants.MaxScriptPublicKeyVersion,
  }

  scp =scp
  inputs := []*externalapi.DomainTransactionInput{{
    PreviousOutpoint: externalapi.DomainOutpoint{
      TransactionID: *txid,
      Index:         0,
    },
    SigOpCount: 1,
    Sequence: math.MaxUint64-1,

    //Sequence: lockTime,
    //SignatureScript: contractr,
    //UTXOEntry: utxo.NewUTXOEntry(transaction.Tx.Outputs[0].Value,transaction.Tx.Outputs[0].ScriptPublicKey,false,0),
    UTXOEntry: utxo.NewUTXOEntry(transaction.Tx.Outputs[0].Value,transaction.Tx.Outputs[0].ScriptPublicKey,false,0),
  }}


	domainTransaction := &externalapi.DomainTransaction{
		Version: constants.MaxTransactionVersion,
		Outputs: outputs,
		Inputs: inputs,
		//LockTime: pushes.LockTime,
		LockTime:     lockTime,
	//	SubnetworkID: externalapi.DomainSubnetworkID{4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		Gas:          0,
		Payload:      []byte{},
	}
  sighashReusedValues := &consensushashing.SighashReusedValues{}

	signature,_ := rawTxInSignature(derivedKey, domainTransaction, 0, consensushashing.SigHashAll, sighashReusedValues, keysFile.ECDSA)
	refundSigScript, _ := refundP2SHContract(contractr,  signature, serializedPublicKey)

  domainTransaction.Inputs[0].SignatureScript =   refundSigScript

  fmt.Println("signature:\n",signature)
  fmt.Println("signatureString:\n",hex.EncodeToString(signature))
  fmt.Println("signatureBlake2b:\n",hex.EncodeToString(getBlake2b(signature)))


  printContract("Initial", contractr)


  printContract("Redeem", refundSigScript)

  rpcTransaction := appmessage.DomainTransactionToRPCTransaction(domainTransaction)
  printRpcTransaction(rpcTransaction)
  fmt.Println("")
  kaspadClient, err := rpcclient.NewRPCClient("localhost:16610")

  if err != nil {
    fmt.Println("error:")
    fmt.Println(err)
  }
  txID,err :=sendTransaction(kaspadClient, rpcTransaction)
  if err != nil {
    log.Fatal(err)
  }
	fmt.Println("Transactions were sent successfully!")
	fmt.Println("Transaction ID(s): ")
  fmt.Printf("\t%s\n", txID)
}
