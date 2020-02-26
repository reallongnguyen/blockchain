package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/boltdb/bolt"
	"golang.org/x/crypto/ripemd160"
)

const (
	targetBits            = 20
	maxNone               = math.MaxInt64
	subsidy               = 8
	genesisAddress        = "donglao"
	genesisData           = "The start of something new"
	addressChecksumLength = 4
	version               = byte(0)
	b58CodeString         = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

// TXInput is ...
type TXInput struct {
	TXid      []byte
	Vout      int
	ScriptSig string
}

// CanUnlockOutputWith is ...
func (txin *TXInput) CanUnlockOutputWith(unlockingData string) bool {
	return txin.ScriptSig == unlockingData
}

// TXOutput is ...
type TXOutput struct {
	Value        int
	ScriptPubKey string
}

// CanBeUnlockedWith is ...
func (txout *TXOutput) CanBeUnlockedWith(unlockingData string) bool {
	return txout.ScriptPubKey == unlockingData
}

// Transaction is ...
type Transaction struct {
	ID   []byte
	Vin  []TXInput
	Vout []TXOutput
}

// SetID generate ID for a transaction
func (tx *Transaction) SetID() {
	var intputHashes [][]byte
	var hash [32]byte

	for _, input := range tx.Vin {
		inputHash := bytes.Join(
			[][]byte{
				input.TXid,
				IntToHex(int64(input.Vout)),
				[]byte(input.ScriptSig),
			},
			[]byte{},
		)
		intputHashes = append(intputHashes, inputHash)
	}

	hash = sha256.Sum256(bytes.Join(intputHashes, []byte{}))
	tx.ID = hash[:]
}

// NewCoinbaseTransaction return coinbase TX
func NewCoinbaseTransaction(to, data string) *Transaction {
	if data == "" {
		data = fmt.Sprintf("Reward to '%s'", to)
	}

	txIn := TXInput{TXid: []byte{}, Vout: -1, ScriptSig: data}
	txOut := TXOutput{Value: subsidy, ScriptPubKey: to}

	return &Transaction{ID: nil, Vin: []TXInput{txIn}, Vout: []TXOutput{txOut}}
}

// IsCoinbase is ...
func (tx *Transaction) IsCoinbase() bool {
	return tx.ID == nil
}

// Block is a unit of blockchain
type Block struct {
	Timestamps  int64
	Transaction []*Transaction
	PrevHash    []byte
	Hash        []byte
	None        int
}

// MineBlock create a block, set hash and return the block pointer
func MineBlock(transaction []*Transaction, prevHash []byte) *Block {
	block := new(Block)

	block.Timestamps = time.Now().Unix()
	block.Transaction = transaction
	block.PrevHash = prevHash

	pow := NewProofOfWork(block)
	none, hash := pow.Run()

	block.Hash = hash
	block.None = none

	return block
}

// HashTransaction return byte array of hash transaction in the block
func (block *Block) HashTransaction() []byte {
	var txHashes [][]byte
	var txHash [32]byte

	for _, transaction := range block.Transaction {
		txHashes = append(txHashes, transaction.ID)
	}

	txHash = sha256.Sum256(bytes.Join(txHashes, []byte{}))

	return txHash[:]
}

// Serialize transmits the block to byte array
func (block *Block) Serialize() []byte {
	var result bytes.Buffer

	encoder := gob.NewEncoder(&result)
	encoder.Encode(block)

	return result.Bytes()
}

// ParseBlock convert byte array to a block
func ParseBlock(data []byte) *Block {
	var block Block

	decoder := gob.NewDecoder(bytes.NewReader(data))
	decoder.Decode(&block)

	return &block
}

// Print is write block information to console
func (block *Block) Print() {
	pow := NewProofOfWork(block)
	isValid := pow.Validate()

	fmt.Printf("%-12s %s\n", "Timestamps:", time.Unix(block.Timestamps, 0))
	fmt.Printf("%-12s %x\n", "Hash:", block.Hash)
	fmt.Printf("%-12s %x\n", "Prev. hash:", block.PrevHash)
	// fmt.Printf("%-12s %s\n", "Data:", block.Data)
	fmt.Printf("%-12s %s\n", "PoW:", strconv.FormatBool(isValid))
	fmt.Println()
}

// Blockchain is a array of block
type Blockchain struct {
	db  *Database
	tip []byte
}

// MineBlock is a method put a block into blockchain
func (bc *Blockchain) MineBlock(transaction []*Transaction) {
	newBlock := MineBlock(transaction, bc.tip)
	bc.db.AddBlock(newBlock)
	bc.tip = newBlock.Hash
}

// NewGenesisBlock create and return the first block in blockchain
func NewGenesisBlock(coinbase *Transaction) *Block {
	return MineBlock([]*Transaction{coinbase}, []byte{})
}

// NewBlockChain create a blockchain which has a first block called Genesis block
func NewBlockChain(db *Database) *Blockchain {
	if isBlank := db.IsBlank(); isBlank {
		log.Println("DB is blank")

		log.Println("Init DB")
		db.InitIfBlank()
	}
	tip := db.GetLastHash()

	if tip == nil {
		log.Println("Create genesis block")
		coinbaseTX := NewCoinbaseTransaction(genesisAddress, genesisData)
		genesis := NewGenesisBlock(coinbaseTX)
		db.AddBlock(genesis)
		tip = genesis.Hash
	}

	return &Blockchain{db, tip}
}

// FindUnspentTransactions is ...
func (bc *Blockchain) FindUnspentTransactions(address string) []Transaction {
	var unspentTXs []Transaction
	spentTXOs := make(map[string][]int)
	bci := bc.Iterator()

	for bci.HasNext() {
		block := bci.Next()

		for _, tx := range block.Transaction {
			txID := hex.EncodeToString(tx.ID)

		Outputs:
			for idx, out := range tx.Vout {
				if spentTXOs[txID] != nil {
					for _, spendOut := range spentTXOs[txID] {
						if idx == spendOut {
							continue Outputs
						}
					}
				}

				if out.CanBeUnlockedWith(address) {
					unspentTXs = append(unspentTXs, *tx)
				}
			}

			if !tx.IsCoinbase() {
				for _, in := range tx.Vin {
					if in.CanUnlockOutputWith(address) {
						inTXid := hex.EncodeToString(in.TXid)
						spentTXOs[inTXid] = append(spentTXOs[inTXid], in.Vout)
					}
				}
			}
		}
	}

	return unspentTXs
}

// FindUTXO is ...
func (bc *Blockchain) FindUTXO(address string) []TXOutput {
	var utxos []TXOutput
	unspentTransactions := bc.FindUnspentTransactions(address)

	for _, tx := range unspentTransactions {
		for _, out := range tx.Vout {
			if out.CanBeUnlockedWith(address) {
				utxos = append(utxos, out)
			}
		}
	}

	return utxos
}

// FindSpentableOutputs is ...
func (bc *Blockchain) FindSpentableOutputs(address string, amount int) (int, map[string][]int) {
	unspentOutputs := make(map[string][]int)
	unspentTXs := bc.FindUnspentTransactions(address)
	acc := 0

Work:
	for _, tx := range unspentTXs {
		txID := hex.EncodeToString(tx.ID)

		for idx, out := range tx.Vout {
			if out.CanBeUnlockedWith(address) {
				acc += out.Value
				unspentOutputs[txID] = append(unspentOutputs[txID], idx)

				if acc >= amount {
					break Work
				}
			}
		}
	}

	return acc, unspentOutputs
}

// NewUTXOTransaction is ...
func (bc *Blockchain) NewUTXOTransaction(from, to string, amount int) *Transaction {
	var inputs []TXInput
	var outputs []TXOutput
	acc, unspentOutputs := bc.FindSpentableOutputs(from, amount)

	if acc < amount {
		log.Fatalln("Not enough funds")
	}

	for txID, outs := range unspentOutputs {
		txIDhex, _ := hex.DecodeString(txID)

		for _, out := range outs {
			input := TXInput{txIDhex, out, from}
			inputs = append(inputs, input)
		}
	}

	sendOutput := TXOutput{amount, to}
	outputs = append(outputs, sendOutput)
	if acc > amount {
		newBalanceOutput := TXOutput{acc - amount, from}
		outputs = append(outputs, newBalanceOutput)
	}

	tx := &Transaction{nil, inputs, outputs}
	tx.SetID()

	return tx
}

// Send is ...
func (bc *Blockchain) Send(from, to string, amount int) {
	tx := bc.NewUTXOTransaction(from, to, amount)
	bc.MineBlock([]*Transaction{tx})
}

// GetBalance is ...
func (bc *Blockchain) GetBalance(address string) (balance int) {
	utxos := bc.FindUTXO(address)

	for _, out := range utxos {
		balance += out.Value
	}

	return
}

// ProofOfWork is a struct containing a block and target
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

// NewProofOfWork is a constructor of ProofOfWork
func NewProofOfWork(block *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))

	return &ProofOfWork{block, target}
}

// IntToHex convert int64 number to hex presented as byte array
func IntToHex(n int64) []byte {
	return []byte(strconv.FormatInt(n, 16))
}

func prepareData(pow *ProofOfWork, none int) []byte {
	block := pow.block
	data := bytes.Join(
		[][]byte{
			block.PrevHash,
			block.HashTransaction(),
			IntToHex(block.Timestamps),
			IntToHex(int64(targetBits)),
			IntToHex(int64(none)),
		},
		[]byte{},
	)

	return data
}

// Run is function start proof of work
func (pow *ProofOfWork) Run() (int, []byte) {
	var hashInt big.Int
	var hash [32]byte
	none := 0

	fmt.Printf("Mining the block has timestamps: %s\n", time.Unix(pow.block.Timestamps, 0))
	for none < maxNone {
		data := prepareData(pow, none)
		hash = sha256.Sum256(data)
		fmt.Printf("\rHash: %x", hash)

		hashInt.SetBytes(hash[:])
		if hashInt.Cmp(pow.target) == -1 {
			break
		}

		none++
	}
	fmt.Println()
	fmt.Println()

	return none, hash[:]
}

// Validate check if block hash is matching with it's data
func (pow *ProofOfWork) Validate() bool {
	var hashInt big.Int

	data := prepareData(pow, pow.block.None)
	hash := sha256.Sum256(data)
	hashInt.SetBytes(hash[:])

	isValid := hashInt.Cmp(pow.target) == -1

	return isValid
}

// Database is struct holding db connection
type Database struct {
	blockBucket []byte
	lastHash    []byte
	db          *bolt.DB
}

// NewDatabase create a database
func NewDatabase() *Database {
	return &Database{blockBucket: []byte("blocks"), lastHash: []byte("l")}
}

// Open a connection to database
func (db *Database) Open(dbName string) {
	boltDB, _ := bolt.Open(dbName, 0600, nil)
	db.db = boltDB
}

// IsBlank check if database is not initial
func (db *Database) IsBlank() (isBlank bool) {
	db.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(db.blockBucket)

		if b == nil {
			isBlank = true
		} else {
			isBlank = false
		}

		return nil
	})

	return
}

// InitIfBlank check database initial status
// if database is not initial then init database
func (db *Database) InitIfBlank() {
	db.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(db.blockBucket)

		if b == nil {
			tx.CreateBucket(db.blockBucket)
		}

		return nil
	})
}

// GetLastHash return last block's hash store in database
func (db *Database) GetLastHash() (lastHash []byte) {
	db.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(db.blockBucket)
		lastHash = b.Get(db.lastHash)

		return nil
	})

	return
}

// AddBlock add a block into database and update last hash
func (db *Database) AddBlock(block *Block) {
	db.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(db.blockBucket)
		b.Put(block.Hash, block.Serialize())
		b.Put(db.lastHash, block.Hash)

		return nil
	})
}

// GetBlock find and return block by hash
func (db *Database) GetBlock(hash []byte) (block *Block) {
	db.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(db.blockBucket)
		encodeBlock := b.Get(hash)
		block = ParseBlock(encodeBlock)

		return nil
	})

	return
}

// Close will close database connection
func (db *Database) Close() {
	db.db.Close()
}

// BlockchainIterator is iterator of blockchain
type BlockchainIterator struct {
	db          *Database
	currentHash []byte
}

// Iterator is method return blockchain iterator
func (bc *Blockchain) Iterator() *BlockchainIterator {
	return &BlockchainIterator{bc.db, bc.tip}
}

// Next return a block then set currentHash to prev. block's hash
func (i *BlockchainIterator) Next() (block *Block) {
	block = i.db.GetBlock(i.currentHash)
	i.currentHash = block.PrevHash

	return
}

// HasNext return true if current hash not nil
func (i *BlockchainIterator) HasNext() bool {
	return len(i.currentHash) != 0
}

// Wallet is struct containing private key and public key
// that will be used to send money
type Wallet struct {
	PrivateKey ecdsa.PrivateKey
	PublicKey  []byte
}

// Wallets is a map that used to store wallets
type Wallets struct {
	wallets map[string]*Wallet
}

// newPairKey generate private key and public key
func newPairKey() (ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()
	private, _ := ecdsa.GenerateKey(curve, rand.Reader)
	pub := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)

	return *private, pub
}

// NewWallet create a wallet
func NewWallet() *Wallet {
	private, pub := newPairKey()
	return &Wallet{private, pub}
}

// HashPubKey is ...
func HashPubKey(key []byte) []byte {
	publicSHA256 := sha256.Sum256(key)

	RIPEMD160Hasher := ripemd160.New()
	RIPEMD160Hasher.Write(publicSHA256[:])
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)

	return publicRIPEMD160
}

// checksum is ...
func checksum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])

	return secondSHA[:addressChecksumLength]
}

// Base58Encode is ...
func Base58Encode(input []byte) []byte {
	var zeros int

	for zeros = 0; input[zeros] == 0; zeros++ {

	}

	size := (len(input)-zeros)*138/100 + 1 // log(256) / log(58), rounded up.

	indexes := make([]int, 0, size)
	bigInt := big.NewInt(0)
	bigInt.SetBytes(input)
	bigInt58 := big.NewInt(58)
	bigInt0 := big.NewInt(0)
	bigIntMod := big.NewInt(0)

	for {
		result, mod := bigInt.DivMod(bigInt, bigInt58, bigIntMod)
		indexes = append(indexes, int(mod.Int64()))

		if result.Cmp(bigInt0) == 0 {
			break
		}
	}

	for i := 0; i < zeros; i++ {
		indexes = append(indexes, 0)
	}

	var b58 []byte
	for i := len(indexes) - 1; i >= 0; i-- {
		b58 = append(b58, b58CodeString[indexes[i]])
	}

	return b58
}

// GetAddress return address of a wallet
func (wallet *Wallet) GetAddress() []byte {
	pubKeyHash := HashPubKey(wallet.PublicKey)
	versionedPayload := append([]byte{version}, pubKeyHash...)
	cs := checksum(versionedPayload)
	fullPayload := append(versionedPayload, cs...)

	address := Base58Encode(fullPayload)

	return address
}

// CLI is a struct that provide cmd interface to interact with blockchain
type CLI struct {
	blockchain *Blockchain
}

// NewCLI is CLI constructor
func NewCLI(blockchain *Blockchain) *CLI {
	return &CLI{blockchain}
}

// Run is ...
func (cli *CLI) Run() {
	sendCmd := flag.NewFlagSet("send", flag.ExitOnError)
	printChainCmd := flag.NewFlagSet("print", flag.ExitOnError)
	getBalanceCmd := flag.NewFlagSet("balance", flag.ExitOnError)
	createWallet := flag.NewFlagSet("createwallet", flag.ExitOnError)

	sendFrom := sendCmd.String("from", "", "Sender address")
	sendTo := sendCmd.String("to", "", "Receiver address")
	sendAmount := sendCmd.Int("amount", 0, "Amount")
	getBalanceAddress := getBalanceCmd.String("address", "", "Address")

	switch os.Args[1] {
	case "send":
		sendCmd.Parse(os.Args[2:])
	case "print":
		printChainCmd.Parse(os.Args[2:])
	case "balance":
		getBalanceCmd.Parse(os.Args[2:])
	case "createwallet":
		createWallet.Parse(os.Args[2:])
	default:
		cli.PrintUsage()
		os.Exit(0)
	}

	if sendCmd.Parsed() {
		if *sendFrom == "" || *sendTo == "" || *sendAmount <= 0 {
			sendCmd.Usage()
			os.Exit(1)
		}

		cli.blockchain.Send(*sendFrom, *sendTo, *sendAmount)
		log.Println("Done")
	}

	if printChainCmd.Parsed() {
		cli.PrintChain()
	}

	if getBalanceCmd.Parsed() {
		if *getBalanceAddress == "" {
			getBalanceCmd.Usage()
			os.Exit(1)
		}

		cli.GetBalance(*getBalanceAddress)
	}

	if createWallet.Parsed() {
		wallet := NewWallet()
		address := wallet.GetAddress()
		fmt.Printf("Your wallet address: %s\n", address)
	}
}

// PrintUsage print instruction of cli
func (cli *CLI) PrintUsage() {
	fmt.Println("This is a tool for interact with blockchain.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println()
	fmt.Printf("\tblockchain <command> [arguments]\n")
	fmt.Println()
	fmt.Println("The commands are:")
	fmt.Println()
	fmt.Printf("\t%-9s %s\n", "send", "send money")
	fmt.Printf("\t%-9s %s\n", "balance", "print balance")
	fmt.Printf("\t%-9s %s\n", "print", "print blocks in blockchain")
}

// PrintChain print data in blockchain
func (cli *CLI) PrintChain() {
	bci := cli.blockchain.Iterator()
	for bci.HasNext() {
		block := bci.Next()
		block.Print()
	}
}

// GetBalance is ...
func (cli *CLI) GetBalance(address string) {
	balance := cli.blockchain.GetBalance(address)

	fmt.Printf("Balance of '%s': %d\n", address, balance)
}

func main() {
	db := NewDatabase()
	db.Open("blockchain.db")
	defer db.Close()

	blockchain := NewBlockChain(db)
	cli := NewCLI(blockchain)

	cli.Run()
}
