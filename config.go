package main
import(
"github.com/kaspanet/kaspad/infrastructure/config"
)

type configFlags struct {
        config.NetworkFlags
}

type signConfig struct {
        KeysFile        string `long:"keys-file" short:"f" description:"Keys file location (default: ~/.kaspawallet/keys.json (*nix), %USERPROFILE%\\AppData\\Local\\Kaspawallet\\key.json (Windows))"`
        Password        string `long:"password" short:"p" description:"Wallet password"`
        Transaction     string `long:"transaction" short:"t" description:"The unsigned transaction(s) to sign on (encoded in hex)"`
        TransactionFile string `long:"transaction-file" short:"F" description:"The file containing the unsigned transaction(s) to sign on (encoded in hex)"`
        config.NetworkFlags
}


