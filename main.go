package main

import (
"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
  "context"
  "log"
  "bytes"
  "github.com/kaspanet/go-secp256k1"
  "path/filepath"

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
  UTXO "github.com/kaspanet/kaspad/domain/consensus/utils/utxo"
  "golang.org/x/crypto/blake2b"
  "github.com/kaspanet/kaspad/infrastructure/network/rpcclient"
  "github.com/kaspanet/kaspad/app/appmessage"


)

const verify = true


const txVersion = 2

var chainParams = &dagconfig.MainnetParams
var (
	flagset     = flag.NewFlagSet("", flag.ExitOnError)
	connectWalletFlag = flagset.String("kaspawallet", "localhost:8082", "host[:port] of kaspawallet  RPC server")
	connectKaspadFlag = flagset.String("kaspad", "localhost:16610", "host[:port] of kaspad RPC server")
//	rpcuserFlag = flagset.String("rpcuser", "", "username for wallet RPC authentication")
//	rpcpassFlag = flagset.String("rpcpass", "", "password for wallet RPC authentication")
	testnetFlag = flagset.Bool("testnet", false, "use testnet network")
	devnetFlag = flagset.Bool("devnet", false, "use devnet network")
	verboseFlag = flagset.Bool("verbose", false, "verbose")
)

const secretSize = 32

var (
  defaultAppDir = util.AppDir("kaspawallet", false)
)
func defaultKeysFile(netParams *dagconfig.Params) string {
  return filepath.Join(defaultAppDir, netParams.Name, "keys.json")
}


var feePerInput = uint64(30000)

var lockTimeInitiateContract = uint64(time.Now().Add(10 * time.Second).Unix()*1000)
var lockTimePartecipateContract = uint64(time.Now().Add(5 * time.Second).Unix()*1000)


var amountInSompi = uint64(1000000)

//kaspad --devnet --utxoindex --archival --nodnsseed  --listen 127.0.0.1:16111 --externalip=127.0.0.1 --allow-submit-block-when-not-synced  --loglevel=trace

// There are two directions that the atomic swap can be performed, as the
// initiator can be on either chain.  This tool only deals with creating the
// Bitcoin transactions for these swaps.  A second tool should be used for the
// transaction on the other chain.  Any chain can be used so long as it supports
// OP_SHA256 and OP_CHECKLOCKTIMEVERIFY.
//
// Example scenerios using bitcoin as the second chain:
//
// Scenerio 1:
//   cp1 initiates (kas)
//   cp2 participates with cp1 H(S) (btc)
//   cp1 redeems btc revealing S
//     - must verify H(S) in contract is hash of known secret
//   cp2 redeems kas with S
//
// Scenerio 2:
//   cp1 initiates (btc)
//   cp2 participates with cp1 H(S) (kas)
//   cp1 redeems kas revealing S
//     - must verify H(S) in contract is hash of known secret
//   cp2 redeems btc with S

func init() {
	flagset.Usage = func() {
		fmt.Println("Usage: btcatomicswap [flags] cmd [cmd args]")
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("  initiate <participant address> <amount>")
		fmt.Println("  participate <initiator address> <amount> <secret hash>")
		fmt.Println("  redeem <contract> <contract transaction> <secret>")
		fmt.Println("  refund <contract> <contract transaction>")
		fmt.Println("  extractsecret <redemption transaction> <secret hash>")
		fmt.Println("  auditcontract <contract> <contract transaction>")
		fmt.Println("  auditcontractonline <contract> <contract transaction>")
		fmt.Println()
		fmt.Println("Flags:")
		flagset.PrintDefaults()
	}
}

type command interface {
	runCommand([]string, pb.KaspawalletdClient, context.Context, *keys.File) error
}

// offline commands don't require wallet RPC.
type offlineCommand interface {
	command
	runOfflineCommand() error
}

type initiateCmd struct {
	cp2Addr *util.AddressPublicKey
	amount  uint64
}

type participateCmd struct {
	cp1Addr    *util.AddressPublicKey
	amount     uint64
	secretHash []byte
}

type redeemCmd struct {
	contract   []byte
	contractTx **externalapi.DomainTransaction
	secret     []byte
}

type refundCmd struct {
	contract   []byte
	contractTx *externalapi.DomainTransaction
}

type extractSecretCmd struct {
	redemptionTx *externalapi.DomainTransaction
	secretHash   []byte
}

type auditContractCmd struct {
	contract   []byte
	contractTx *externalapi.DomainTransaction
}
type auditContractOnlineCmd struct {
	contract   []byte
	contractTx *externalapi.DomainTransaction
}

func main() {
	err, showUsage := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	if showUsage {
		flagset.Usage()
	}
	if err != nil || showUsage {
		os.Exit(1)
	}
}

func checkCmdArgLength(args []string, required int) (nArgs int) {
	if len(args) < required {
		return 0
	}
	for i, arg := range args[:required] {
		if len(arg) != 1 && strings.HasPrefix(arg, "-") {
			return i
		}
	}
	return required
}

func run() (err error, showUsage bool) {
	flagset.Parse(os.Args[1:])
	args := flagset.Args()
	if len(args) == 0 {
		return nil, true
	}
	cmdArgs := 0
	switch args[0] {
	case "initiate":
		cmdArgs = 2
	case "participate":
		cmdArgs = 3
	case "redeem":
		cmdArgs = 3
	case "refund":
		cmdArgs = 2
	case "extractsecret":
		cmdArgs = 2
	case "auditcontract":
		cmdArgs = 2
	case "auditcontractonline":
		cmdArgs = 2
	default:
		return fmt.Errorf("unknown command %v", args[0]), true
	}
	nArgs := checkCmdArgLength(args[1:], cmdArgs)
	flagset.Parse(args[1+nArgs:])
	if nArgs < cmdArgs {
		return fmt.Errorf("%s: too few arguments", args[0]), true
	}
	if flagset.NArg() != 0 {
		return fmt.Errorf("unexpected argument: %s", flagset.Arg(0)), true
	}

	if *testnetFlag {
		chainParams = &dagconfig.TestnetParams
	}
  if *devnetFlag {
		chainParams = &dagconfig.DevnetParams
	}



	var cmd command
	switch args[0] {
	case "initiate":
		cp2Addr, err := util.DecodeAddress(args[1], chainParams.Prefix)
		if err != nil {
			return fmt.Errorf("failed to decode participant address: %v", err), true
		}
		if !cp2Addr.IsForPrefix(chainParams.Prefix) {
			return fmt.Errorf("participant address is not "+
				"intended for use on %v", chainParams.Name), true
		}
		cp2AddrP2PKH, ok := cp2Addr.(*util.AddressPublicKey)
		if !ok {
			return errors.New("participant address is not P2PKH"), true
		}

		amountF64, err := strconv.ParseFloat(args[2], 64)
		if err != nil {
			return fmt.Errorf("failed to decode amount: %v", err), true
		}
		amount := uint64(amountF64)* uint64(constants.SompiPerKaspa)

		cmd = &initiateCmd{cp2Addr: cp2AddrP2PKH, amount: amount}

  case "participate":
    cp1Addr, err := util.DecodeAddress(args[1], chainParams.Prefix)
    if err != nil {
      return fmt.Errorf("failed to decode initiator address: %v", err), true
    }
    /*if !cp1Addr.IsForNet(chainParams) {
      return fmt.Errorf("initiator address is not "+
        "intended for use on %v", chainParams.Name), true
    }*/
    cp1AddrP2PKH, ok := cp1Addr.(*util.AddressPublicKey)
    if !ok {
      return errors.New("initiator address is not P2PKH"), true
    }

    amountF64, err := strconv.ParseFloat(args[2], 64)
    if err != nil {
      return fmt.Errorf("failed to decode amount: %v", err), true
    }
		amount := uint64(amountF64)* uint64(constants.SompiPerKaspa)
    if err != nil {
      return err, true
    }

    secretHash, err := hex.DecodeString(args[3])
    if err != nil {
      return errors.New("secret hash must be hex encoded"), true
    }
    if len(secretHash) != sha256.Size {
      return errors.New("secret hash has wrong size"), true
    }

    cmd = &participateCmd{cp1Addr: cp1AddrP2PKH, amount: amount, secretHash: secretHash}
  case "redeem":
    contract, err := hex.DecodeString(args[1])
    if err != nil {
      return fmt.Errorf("failed to decode contract: %v", err), true
    }

    contractTxBytes, err := hex.DecodeString(args[2])
    if err != nil {
      return fmt.Errorf("failed to decode contract transaction: %v", err), true
    }
    contractTx, _ := serialization.DeserializeDomainTransaction(contractTxBytes)

    secret, err := hex.DecodeString(args[3])
    if err != nil {
      return fmt.Errorf("failed to decode secret: %v", err), true
    }

    cmd = &redeemCmd{contract: contract, contractTx: &contractTx, secret: secret}

  case "refund":
    contract, err := hex.DecodeString(args[1])
    if err != nil {
      return fmt.Errorf("failed to decode contract: %v", err), true
    }

    contractTxBytes, err := hex.DecodeString(args[2])
    if err != nil {
      return fmt.Errorf("failed to decode contract transaction: %v", err), true
    }
    contractTx, _ := serialization.DeserializeDomainTransaction(contractTxBytes)

    cmd = &refundCmd{contract: contract, contractTx: contractTx}

  case "extractsecret":
    redemptionTxBytes, err := hex.DecodeString(args[1])
    if err != nil {
      return fmt.Errorf("failed to decode redemption transaction: %v", err), true
    }

    redemptionTx, err := serialization.DeserializeDomainTransaction(redemptionTxBytes)
    if err != nil {
      fmt.Println("impossible to parse redemption")
      log.Fatal(err)
    }

    secretHash, err := hex.DecodeString(args[2])
    if err != nil {
      return errors.New("secret hash must be hex encoded"), true
    }
    if len(secretHash) != sha256.Size {
      return errors.New("secret hash has wrong size"), true
    }

    cmd = &extractSecretCmd{redemptionTx: redemptionTx, secretHash: secretHash}

  case "auditcontract":
    contract, err := hex.DecodeString(args[1])
    if err != nil {
      return fmt.Errorf("failed to decode contract: %v", err), true
    }

    contractTxBytes, err := hex.DecodeString(args[2])
    if err != nil {
      return fmt.Errorf("failed to decode contract transaction: %v", err), true
    }

    contractTx, _ := serialization.DeserializeDomainTransaction(contractTxBytes)

    cmd = &auditContractCmd{contract: contract, contractTx: contractTx}

  case "auditcontractonline":
    contract, err := hex.DecodeString(args[1])
    if err != nil {
      return fmt.Errorf("failed to decode contract: %v", err), true
    }

    contractTxBytes, err := hex.DecodeString(args[2])
    if err != nil {
      return fmt.Errorf("failed to decode contract transaction: %v", err), true
    }

    contractTx, _ := serialization.DeserializeDomainTransaction(contractTxBytes)
    cmd = &auditContractOnlineCmd{contract: contract, contractTx: contractTx}
	}

	// Offline commands don't need to talk to the wallet.
	if cmd, ok := cmd.(offlineCommand); ok {
		return cmd.runOfflineCommand(), false
	}

  daemonClient, tearDown, err := client.Connect(*connectWalletFlag)
  if err != nil {
    log.Fatal(err)
  }
  defer tearDown()
  ctx, cancel := context.WithTimeout(context.Background(), (10 * time.Minute))
  defer cancel()

  keysFile, _ := keys.ReadKeysFile(chainParams, defaultKeysFile(chainParams))

  password := keys.GetPassword("Password:")
  mnemonics, _ := keysFile.DecryptMnemonics(password)

	err = cmd.runCommand(mnemonics,daemonClient,ctx,keysFile)
	return err, false
}

func normalizeAddress(addr string, defaultPort string) (hostport string, err error) {
	host, port, origErr := net.SplitHostPort(addr)
	if origErr == nil {
		return net.JoinHostPort(host, port), nil
	}
	addr = net.JoinHostPort(addr, defaultPort)
	_, _, err = net.SplitHostPort(addr)
	if err != nil {
		return "", origErr
	}
	return addr, nil
}

func walletPort(params *dagconfig.Params) string {
	switch params {
	case &dagconfig.MainnetParams:
		return "8332"
	case &dagconfig.TestnetParams:
		return "18332"
	case &dagconfig.DevnetParams:
		return "18332"
	default:
		return "8082"
	}
}

func printDomainTransaction(tx *externalapi.DomainTransaction) {
	fmt.Printf("Transaction ID: \t%s\n", consensushashing.TransactionID(tx))
	fmt.Println()
  fmt.Println("Inputs:")
	allInputSompi := uint64(0)
	for index, input := range tx.Inputs {
    allInputSompi += uint64(input.UTXOEntry.Amount())
    fmt.Printf("\t%v:%d\tAmount: %.8f Kaspa\n",input.PreviousOutpoint.TransactionID,index,getKaspaXSompi(input.UTXOEntry.Amount()))
  }
  fmt.Println("\nOutputs:")
  allOutputSompi := uint64(0)
  for index,output := range(tx.Outputs){
    scriptPublicKeyType, scriptPublicKeyAddress, err := txscript.ExtractScriptPubKeyAddress(output.ScriptPublicKey, chainParams)
    if err != nil {
      log.Fatal(err)
    }

    addressString := scriptPublicKeyAddress.EncodeAddress()
    if scriptPublicKeyType == txscript.NonStandardTy {
      scriptPublicKeyHex := hex.EncodeToString(output.ScriptPublicKey.Script)
      addressString = fmt.Sprintf("<Non-standard transaction script public key: %s>", scriptPublicKeyHex)
    }
    fmt.Printf("\t%d:%s\tAmount: %.8f Kaspa\n",
      index, addressString, getKaspaXSompi(output.Value))

    allOutputSompi += uint64(output.Value)

  }
  fmt.Println("")
	fmt.Printf("Fee:\t%d Sompi\n", allInputSompi-allOutputSompi)
	fmt.Printf("GAS:\t%d Sompi\n", tx.Gas)
	fmt.Printf("LockTime:\t%d \n", tx.LockTime)
  fmt.Println("")
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

func derivedKeyToSchnorrKeypair(extendedKey *bip32.ExtendedKey) *secp256k1.SchnorrKeyPair{
  privateKey := extendedKey.PrivateKey()
  schnorrKeyPair,_ := privateKey.ToSchnorr()
  return schnorrKeyPair


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

func searchAddressByBlake2b(addresses []string, blake []byte, extendedPublicKeys []string, ecdsa bool) (*util.Address, *string) {
  for i := range addresses {
    path := fmt.Sprintf("m/%d/%d", libkaspawallet.ExternalKeychain, i+1)
    new_address, _ := libkaspawallet.Address(chainParams, extendedPublicKeys, 1, path, ecdsa)
    if hex.EncodeToString(getBlake2b(new_address.ScriptAddress())) == hex.EncodeToString(blake){
      return &new_address, &path
    }
  }
  return nil,nil
}

func getAddressPath(addresses []string, address string, extendedPublicKeys []string, ecdsa bool) *string {
  for i, taddress := range addresses {
    if taddress == address {
      path := fmt.Sprintf("m/%d/%d", libkaspawallet.ExternalKeychain, i+1)
      new_address, _ := libkaspawallet.Address(chainParams, extendedPublicKeys, 1, path, ecdsa)
      if address == new_address.EncodeAddress() {
        return &path
      }
    }
  }
  return nil
}

func getAddresses(daemonClient pb.KaspawalletdClient, ctx context.Context) []string {
  addressesResponse, err := daemonClient.ShowAddresses(ctx, &pb.ShowAddressesRequest{})
  if err != nil {
    log.Fatal(err)
    return []string{}
  }
  return addressesResponse.Address
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

func defaultPath(isMultisig bool) string {
  purpose := SingleSignerPurpose
  if isMultisig {
    purpose = MultiSigPurpose
  }

  return fmt.Sprintf("m/%d'/%d'/0'", purpose, CoinType)
}

const (
  SingleSignerPurpose = 44
  // Note: this is not entirely compatible to BIP 45 since
  // BIP 45 doesn't have a coin type in its derivation path.
  MultiSigPurpose = 45
  // TODO: Register the coin type in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
  CoinType = 111111
)

func printAddressPushes(name string, addresses []string ,blake []byte,keysFile *keys.File)(*util.Address, *string){
  var addr *util.Address
  var path *string
  if keysFile != nil{
    addr, path = searchAddressByBlake2b(addresses,blake,keysFile.ExtendedPublicKeys, keysFile.ECDSA)
  }
  if *verboseFlag {
    fmt.Println("Pushes -", name,"from Contract:")
    if addr!=nil {
       fmt.Println(*addr)
    }
    fmt.Println(hex.EncodeToString(blake))
    fmt.Println("")
  }
  if addr != nil {
    return addr, path
  } else {
    return nil,nil
  }


}

func parsePushes(contractr []byte,addresses []string, keysFile *keys.File)(*util.Address, *string, []byte, *util.Address, *string, []byte, string, int64, uint64){
  pushes, err := txscript.ExtractAtomicSwapDataPushes(0, contractr)
  if err != nil {
    log.Fatal(err)
  }
  if pushes == nil {
    log.Fatal("contract is not an atomic swap script recognized by this tool")
  }
  recipientAddr, recipient_path := printAddressPushes("Recipient", addresses, pushes.RecipientBlake2b[:], keysFile)
  refundAddr, refund_path := printAddressPushes("Refund", addresses, pushes.RefundBlake2b[:], keysFile)

  if *verboseFlag{
    fmt.Println("Pushes - Secret hash from Contract:")
    fmt.Println(hex.EncodeToString(pushes.SecretHash[:]))
    fmt.Println("")

    fmt.Println("Pushes - Secret size from Contract:")
    fmt.Println(pushes.SecretSize)
    fmt.Println("")

    fmt.Println("Pushes - LockTime from Contract:")
    fmt.Println(pushes.LockTime, "-",time.Unix(int64(pushes.LockTime/1000), 0))
    fmt.Println("")
  }
  return recipientAddr, recipient_path, pushes.RecipientBlake2b[:], refundAddr, refund_path, pushes.RefundBlake2b[:], hex.EncodeToString(pushes.SecretHash[:]), pushes.SecretSize, pushes.LockTime
}

// sendRawTransaction calls the signRawTransaction JSON-RPC method.  It is
// implemented manually as client support is currently outdated from the
// btcd/rpcclient package.
func sendRawTransaction(tx externalapi.DomainTransaction) (*string, error) {
  rpcTransaction := appmessage.DomainTransactionToRPCTransaction(&tx)
  kaspadClient, err := rpcclient.NewRPCClient(*connectKaspadFlag)

  if err != nil {
    fmt.Println("impossible to connect to kaspad ",*connectKaspadFlag,err)
    return nil,err
  }
  txID,err :=sendTransaction(kaspadClient, rpcTransaction)
  if err != nil {
    fmt.Println("impossible to send transaction",err)
    return nil,err
  }
  fmt.Println("Transactions were sent successfully!")
  fmt.Println("Transaction ID(s): ")
  fmt.Printf("\t%s\n", txID)
  return &txID,nil

}

func sendTransaction(client *rpcclient.RPCClient, rpcTransaction *appmessage.RPCTransaction) (string, error) {
  submitTransactionResponse, err := client.SubmitTransaction(rpcTransaction, true)
  if err != nil {
    return "", errors.Wrapf(err, "error submitting transaction")
  }
  return submitTransactionResponse.TransactionID, nil
}


// getRawChangeAddress calls the getrawchangeaddress JSON-RPC method.  It is
// implemented manually as the rpcclient implementation always passes the
// account parameter which was removed in Bitcoin Core 0.15.
func getRawChangeAddress(daemonClient pb.KaspawalletdClient, ctx context.Context) (util.Address,) {
  changeAddrs, _ := daemonClient.NewAddress(ctx, &pb.NewAddressRequest{})
  changeAddr, _ := util.DecodeAddress(changeAddrs.Address, chainParams.Prefix)
  return changeAddr
}

func promptPublishTx(tx externalapi.DomainTransaction, name string, daemonClient pb.KaspawalletdClient, ctx context.Context) error {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Publish %s transaction? [y/N] ", name)
		answer, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		answer = strings.TrimSpace(strings.ToLower(answer))

		switch answer {
		case "y", "yes":
		case "n", "no", "":
			return nil
		default:
			fmt.Println("please answer y or n")
			continue
		}
    txID,err:=sendRawTransaction(tx)
		if err != nil {
			return fmt.Errorf("sendrawtransaction: %v", err)
		}
		fmt.Printf("Published %s transaction (%v)\n", name, txID)
		return nil
	}
}

// contractArgs specifies the common parameters used to create the initiator's
// and participant's contract.
type contractArgs struct {
	them       *util.AddressPublicKey
	amount     uint64
	locktime   uint64
	secretHash []byte
}

type spendArgs struct {
	them       *util.AddressPublicKey
	amount     uint64
	locktime   uint64
	secretHash []byte
  secret     []byte
}

// builtContract houses the details regarding a contract and the contract
// payment transaction, as well as the transaction to perform a refund.
type builtContract struct {
	contract       []byte
	contractP2SH   util.Address
	contractTxHash []byte
	contractTx     *externalapi.DomainTransaction
	contractFee    uint64
	refundTx       *externalapi.DomainTransaction
	refundFee      uint64
}

func getContractIn(amount uint64, daemonClient pb.KaspawalletdClient, ctx context.Context, keysFile *keys.File) ([]*externalapi.DomainTransactionInput,uint64,[]string){
  kaspadClient, _ := rpcclient.NewRPCClient(*connectKaspadFlag)
  addressesResponse, _ := daemonClient.ShowAddresses(ctx, &pb.ShowAddressesRequest{})

  getUTXOsByAddressesResponse,_  := kaspadClient.GetUTXOsByAddresses(addressesResponse.Address)


  inputs := []*externalapi.DomainTransactionInput{}
  input_amount := uint64(0)
  done := false
  change := uint64(0)
  var paths []string

  dagInfo, _ := kaspadClient.GetBlockDAGInfo()
  for _, entry := range getUTXOsByAddressesResponse.Entries {
    if !isUTXOSpendable(entry, dagInfo.VirtualDAAScore) {
      continue
    }
    if input_amount < ( amount+ getFee(inputs)) {
      address := entry.Address
      address_path := getAddressPath(addressesResponse.Address,address,keysFile.ExtendedPublicKeys, keysFile.ECDSA)
      paths = append(paths, *address_path)
      txid, _ := externalapi.NewDomainTransactionIDFromString(entry.Outpoint.TransactionID)
      script_pub_key,_ := hex.DecodeString(entry.UTXOEntry.ScriptPublicKey.Script)
      inputs = append(inputs, &externalapi.DomainTransactionInput{PreviousOutpoint: externalapi.DomainOutpoint{
          TransactionID:    *txid,
          Index:            entry.Outpoint.Index,
        },
        SigOpCount:         1,
        UTXOEntry: UTXO.NewUTXOEntry(
          entry.UTXOEntry.Amount,
          &externalapi.ScriptPublicKey{
            Version: uint16(entry.UTXOEntry.ScriptPublicKey.Version),
            Script: script_pub_key,
          },
          entry.UTXOEntry.IsCoinbase,
          entry.UTXOEntry.BlockDAAScore,
        ),
      })

      input_amount += uint64(entry.UTXOEntry.Amount)
      change = input_amount - amount
    }else{
      done = true
      break
    }
  }
  if !done{
    log.Fatal("not enough inputs to spend")
  }
  return inputs,  change, paths
}



func isUTXOSpendable(entry *appmessage.UTXOsByAddressesEntry, virtualSelectedParentBlueScore uint64) bool {
  blockDAAScore := entry.UTXOEntry.BlockDAAScore
  if !entry.UTXOEntry.IsCoinbase {
    const minConfirmations = 10
    return blockDAAScore+minConfirmations < virtualSelectedParentBlueScore
  }
  coinbaseMaturity := chainParams.BlockCoinbaseMaturity
  return blockDAAScore+coinbaseMaturity < virtualSelectedParentBlueScore
}

// builtContract houses the details regarding a contract and the contract
// payment transaction, as well as the transaction to perform a refund.


// buildContract creates a contract for the parameters specified in args, using
// wallet RPC to generate an internal address to redeem the refund and to sign
// the payment to the contract transaction.
func buildContract(daemonClient pb.KaspawalletdClient, ctx context.Context, mnemonics []string, keysFile *keys.File, args *contractArgs) (*builtContract, error) {
	refundAddr := getRawChangeAddress(daemonClient,ctx)
	refundAddrH := getBlake2b(refundAddr.ScriptAddress())
  themAddrH := getBlake2b(args.them.ScriptAddress())
	contract, err := atomicSwapContract(refundAddrH, themAddrH,
		args.locktime, args.secretHash)
	if err != nil {
		return nil, err
	}
	contractP2SH, err := util.NewAddressScriptHash(contract, chainParams.Prefix)
	if err != nil {
		return nil, err
	}

  contractP2SHPkScript, err := txscript.PayToScriptHashScript(contract)

	if err != nil {
		return nil, err
	}

  inputs,  changeAmount, paths := getContractIn(args.amount, daemonClient,ctx, keysFile)

  changeAddrs, _ := daemonClient.NewAddress(ctx, &pb.NewAddressRequest{})
  changeAddr, _ := util.DecodeAddress(changeAddrs.Address, chainParams.Prefix)
  changeAddressScript, _ := txscript.PayToAddrScript(changeAddr)

  domainTransaction := &externalapi.DomainTransaction{
    Version: constants.MaxTransactionVersion,
    Inputs:  inputs,
    Outputs: []*externalapi.DomainTransactionOutput{
      {
        Value: uint64(args.amount),
        ScriptPublicKey: &externalapi.ScriptPublicKey{
          Version: constants.MaxScriptPublicKeyVersion,
          Script:  contractP2SHPkScript,
        },
      },
      {
        Value: uint64(changeAmount)-getFee(inputs),
        ScriptPublicKey: changeAddressScript,
      },
    },
    LockTime:     0,
    SubnetworkID: subnetworks.SubnetworkIDNative,
    Gas:          0,
    Payload:      nil,
  }
  // Sign all inputs in transaction

  for i, input := range domainTransaction.Inputs {
    derivedKey,_ := getKeys(paths[i],mnemonics, keysFile)
    keyPair := derivedKeyToSchnorrKeypair(derivedKey)
    signatureScript, err := txscript.SignatureScript(domainTransaction, i, consensushashing.SigHashAll, keyPair,
      &consensushashing.SighashReusedValues{})
    if err != nil {
      return nil, err
    }
    input.SignatureScript = signatureScript
  }


  refundTx, refundFee := buildSpend(contract, domainTransaction, nil, mnemonics,daemonClient,ctx,keysFile)
  txHash,err := serialization.SerializeDomainTransaction(domainTransaction)
  if err != nil {
    log.Fatal(err)
  }

  return &builtContract{
    contract: contract,
    contractP2SH: contractP2SH,
    contractTxHash: txHash,
    contractTx: domainTransaction,
    contractFee: getFee(inputs),
    refundTx: refundTx,
    refundFee: refundFee,
  }, nil
}

func getKeys(path string, mnemonics []string, keysFile *keys.File)(*bip32.ExtendedKey, []byte){
  extendedKey, _ := extendedKeyFromMnemonicAndPath(mnemonics[0], defaultPath(false), chainParams)
  derivedKey, err := extendedKey.DeriveFromPath(path)
  if err != nil { log.Fatal(err)}
  return derivedKey, getSerializedPublicKey(derivedKey, keysFile)
}

func getSerializedPublicKey(derivedKey *bip32.ExtendedKey, keysFile *keys.File)([]byte){
  publicKey,_ := derivedKey.PublicKey()
  if keysFile.ECDSA {
    serializedECDSAPublicKey, err := publicKey.Serialize()
    if err != nil {
      log.Fatal("impossible to serialize public key")
    }
  return serializedECDSAPublicKey[:]
  } else {
    publicKey.ToSchnorr()
    schnorrPublicKey, err := publicKey.ToSchnorr()
    if err != nil {
      log.Fatal("impossible to get schnorr public key")
    }
    serializedSchnorrPublicKey, err := schnorrPublicKey.Serialize()
    if err != nil {
      log.Fatal("impossible to serialize schnorr public key")
    }
    return serializedSchnorrPublicKey[:]

  }
}

func getFee(inputs []*externalapi.DomainTransactionInput) uint64{
  return uint64(feePerInput)*uint64(len(inputs)+1)
}

func getContractOut(contractr []byte, tx *externalapi.DomainTransaction) int {
  contractHash, _ := txscript.PayToScriptHashScript(contractr)
  for idx, outputs := range tx.Outputs {
    if hex.EncodeToString(contractHash) == hex.EncodeToString(outputs.ScriptPublicKey.Script){
      return idx
    }
  }
  panic("contract not fonud")
}

func buildSpend(contract []byte,transaction *externalapi.DomainTransaction, secret *[]byte, mnemonics []string, daemonClient pb.KaspawalletdClient, ctx context.Context, keysFile *keys.File)(*externalapi.DomainTransaction, uint64) {
  contract_idx := getContractOut(contract,transaction)
  txid := consensushashing.TransactionID(transaction)

  addressesResponse,  err := daemonClient.ShowAddresses(ctx, &pb.ShowAddressesRequest{})
  if err != nil{
    log.Fatal(err)
  }
  addresses := addressesResponse.Address
  redeemAddr, redeem_path,_, refundAddr, refund_path, _, _, _, lockTime := parsePushes(contract, addresses,keysFile)
  isRedeem := (secret != nil)
  if (refundAddr == nil || refund_path == nil) && !isRedeem {
    log.Fatal("refundAddress is unknown I'm not able to sign refund transaction")
  } else {
    if (redeemAddr == nil || redeem_path == nil) && isRedeem{
      log.Fatal("redeemAddress is unknown I'm not able to sign redeem transaction")
    }
  }
  var recipientAddr *util.Address
  var recipient_path *string
  if isRedeem{
    lockTime=uint64(0)
    recipientAddr = redeemAddr
    recipient_path = redeem_path
  }else{
    recipientAddr=refundAddr
    recipient_path = refund_path
  }
  derivedKey,serializedPublicKey := getKeys(*recipient_path,mnemonics,keysFile)
  inputs := []*externalapi.DomainTransactionInput{{
    PreviousOutpoint: externalapi.DomainOutpoint{
      TransactionID: *txid,
      Index:         0,
    },
    SigOpCount: 1,
    //  Sequence: math.MaxUint64-1,
    UTXOEntry: UTXO.NewUTXOEntry(transaction.Outputs[contract_idx].Value,transaction.Outputs[contract_idx].ScriptPublicKey,false,0),
  }}

  spend_fees := getFee(inputs)

  script_pubkey, _ := txscript.PayToAddrScript(*recipientAddr)

  outputs := []*externalapi.DomainTransactionOutput{{
    Value:           (transaction.Outputs[0].Value - spend_fees) ,
    ScriptPublicKey: script_pubkey,
  }}

  domainTransaction := &externalapi.DomainTransaction{
    Version: constants.MaxTransactionVersion,
    Outputs: outputs,
    Inputs: inputs,
    LockTime:     lockTime,
    Gas:          0,
    Payload:      []byte{},
  }
  sighashReusedValues := &consensushashing.SighashReusedValues{}
  signature,_ := rawTxInSignature(derivedKey, domainTransaction, 0, consensushashing.SigHashAll, sighashReusedValues, keysFile.ECDSA)

  var sigScript []byte
  if isRedeem{
    sigScript, _ = redeemP2SHContract(contract,  signature, serializedPublicKey, *secret)
  } else {
    sigScript, _ = refundP2SHContract(contract,  signature, serializedPublicKey)
  }
  domainTransaction.Inputs[0].SignatureScript =   sigScript

  return domainTransaction, spend_fees
}

func sha256Hash(x []byte) []byte {
	h := sha256.Sum256(x)
	return h[:]
}

func (cmd *initiateCmd) runCommand(mnemonics []string, daemonClient pb.KaspawalletdClient, ctx context.Context, keysFile *keys.File) error {
	var secret [secretSize]byte
	_, err := rand.Read(secret[:])
	if err != nil {
		return err
	}
	secretHash := sha256Hash(secret[:])

	// locktime after 500,000,000 (Tue Nov  5 00:53:20 1985 UTC) is interpreted
	// as a unix time rather than a block height.

	b, err := buildContract(daemonClient, ctx, mnemonics, keysFile,
    &contractArgs{
		  them:       cmd.cp2Addr,
      amount:     cmd.amount,
		  locktime:   lockTimeInitiateContract,
		  secretHash: secretHash,
	  })
	if err != nil {
		return err
	}
  printCommand(secret[:],secretHash,b)
	return promptPublishTx(*b.contractTx, "contract",daemonClient,ctx)
}

func printTransaction(tx *externalapi.DomainTransaction, name string){
  if *verboseFlag {
    printDomainTransaction(tx)
  }
  fmt.Printf("%v transaction (%v):\n", name, consensushashing.TransactionID(tx))
  txHash,err  := serialization.SerializeDomainTransaction(tx)
  if err != nil{
    log.Fatal("Impossible To deserialize %v Transaction:",name, tx)
  }
  fmt.Printf("%x\n\n", txHash)

}

func printCommand(secret []byte, secretHash []byte, b *builtContract){
  if secret != nil{
	  fmt.Printf("Secret:      %x\n", secret)
  }
	fmt.Printf("Secret hash: %x\n\n", secretHash)
	fmt.Printf("Contract (%v):\n", b.contractP2SH)
	fmt.Printf("%x\n\n", b.contract)
  printTransaction(b.contractTx, "ContractTx")
  printTransaction(b.refundTx,"RefundTx")

}

func (cmd *participateCmd) runCommand(mnemonics []string, daemonClient pb.KaspawalletdClient, ctx context.Context, keysFile *keys.File) error {
	// locktime after 500,000,000 (Tue Nov  5 00:53:20 1985 UTC) is interpreted
	// as a unix time rather than a block height.
	b, err := buildContract(daemonClient, ctx, mnemonics, keysFile,
	  &contractArgs{
		  them:       cmd.cp1Addr,
		  amount:     cmd.amount,
		  locktime:   lockTimePartecipateContract,
		  secretHash: cmd.secretHash,
	})
	if err != nil {
		return err
	}

  printCommand(nil,cmd.secretHash,b)

	return promptPublishTx(*b.contractTx, "contract", daemonClient, ctx)
}

func (cmd *redeemCmd) runCommand(mnemonics []string, daemonClient pb.KaspawalletdClient, ctx context.Context, keysFile *keys.File) error {
  redeemTx,_ := buildSpend(cmd.contract, *cmd.contractTx, &cmd.secret, mnemonics,daemonClient,ctx,keysFile)
  printTransaction(redeemTx,"RedeemTx")
	return promptPublishTx(*redeemTx, "redeem",daemonClient,ctx)
}

func (cmd *refundCmd) runCommand(mnemonics []string, daemonClient pb.KaspawalletdClient, ctx context.Context, keysFile *keys.File) error {
  refundTx,_ := buildSpend(cmd.contract, cmd.contractTx, nil, mnemonics,daemonClient,ctx,keysFile)
  printTransaction(refundTx,"RefundTx")
	return promptPublishTx(*refundTx, "refund",daemonClient,ctx)
}

func (cmd *extractSecretCmd) runCommand(mnemonics []string, daemonClient pb.KaspawalletdClient, ctx context.Context, keysFile *keys.File) error {
	return cmd.runOfflineCommand()
}

func (cmd *extractSecretCmd) runOfflineCommand() error {
	// Loop over all pushed data from all inputs, searching for one that hashes
	// to the expected hash.  By searching through all data pushes, we avoid any
	// issues that could be caused by the initiator redeeming the participant's
	// contract with some "nonstandard" or unrecognized transaction or script
	// type.
	for _, in := range cmd.redemptionTx.Inputs {
		pushes, err := txscript.PushedData(in.SignatureScript)
		if err != nil {
			return err
		}
		for _, push := range pushes {
			if bytes.Equal(sha256Hash(push), cmd.secretHash) {
				fmt.Printf("Secret: %x\n", push)
				return nil
			}
		}
	}
	return errors.New("transaction does not contain the secret")
}

func (cmd *auditContractCmd) runCommand(mnemonics []string, daemonClient pb.KaspawalletdClient, ctx context.Context, keysFile *keys.File) error {
	return cmd.runOfflineCommand()
}

func (cmd *auditContractOnlineCmd) runCommand(mnemonics []string, daemonClient pb.KaspawalletdClient, ctx context.Context, keysFile *keys.File) error {
  addresses := getAddresses(daemonClient,ctx)
  redeem_addr, _, redeem2b, refund_addr, _, refund2b, secretHash, pushesSecretSize, locktime := parsePushes(cmd.contract,addresses,keysFile)
  printAuditResult(cmd.contract,cmd.contractTx,redeem_addr,redeem2b,refund_addr,refund2b,secretHash,pushesSecretSize,locktime)


	return nil
}

func getKaspaXSompi(value uint64) float64{
  return float64(value)/float64(constants.SompiPerKaspa)
}

func printAuditResult(contract []byte, contractTx *externalapi.DomainTransaction , recipient_addr *util.Address, recipient2b []byte, refund_addr *util.Address, refund2b []byte, secretHash string, pushesSecretSize int64, locktime uint64 ) error{
  idx := getContractOut(contract,contractTx)
  if pushesSecretSize != secretSize {
    return fmt.Errorf("contract specifies strange secret size %v", pushesSecretSize)
  }

  contractP2SH, err := util.NewAddressScriptHash(contract, chainParams.Prefix)
  if err != nil {
    log.Fatal(err)
  }

  fmt.Printf("Contract address:         %v\n", contractP2SH)
  fmt.Printf("Contract value:           %.8f\n", getKaspaXSompi(contractTx.Outputs[idx].Value))
  fmt.Printf("Recipient blake2b:        %x\n", recipient2b)
  if recipient_addr != nil {
    fmt.Printf("Recipient address:        %v\n", *recipient_addr)
  }
  fmt.Printf("Author's refund blake2b:  %x\n", refund2b)
  if refund_addr != nil {
    fmt.Printf("Autor's refund address:   %v\n", *refund_addr)
  }
  fmt.Println("")
  fmt.Printf("Secret hash(len:%d):      %v\n\n", secretSize, secretHash)

  if locktime>= uint64(constants.LockTimeThreshold) {
    t := time.Unix(int64(locktime/1000), 0)
    fmt.Printf("Locktime: %v\n", t.UTC())
    reachedAt := time.Until(t).Truncate(time.Second)
    if reachedAt > 0 {
      fmt.Printf("Locktime reached in %v\n", reachedAt)
    } else {
      fmt.Printf("Contract refund time lock has expired\n")
    }
  } else {
    fmt.Printf("Locktime: block %v\n", locktime)
  }

  return nil
}

func (cmd *auditContractCmd) runOfflineCommand() error {
  _, _, redeem2b, _, _, refund2b, secretHash, pushesSecretSize, locktime := parsePushes(cmd.contract,[]string{},nil)
  printAuditResult(cmd.contract,cmd.contractTx,nil,redeem2b,nil,refund2b,secretHash,pushesSecretSize,locktime)
  return nil
}


// atomicSwapContract returns an output script that may be redeemed by one of
// two signature scripts:
//
//   <their sig> <their pubkey> <initiator secret> 1
//
//   <my sig> <my pubkey> 0
//
// The first signature script is the normal redemption path done by the other
// party and requires the initiator's secret.  The second signature script is
// the refund path performed by us, but the refund can only be performed after
// locktime.
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

    //removed as SomeOne235 commit in txscripts extractAtomicSwapDataPushes
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

