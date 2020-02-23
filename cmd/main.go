package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"flag"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/boltdb/bolt"
)

const (
	targetBits = 20
	maxNone    = math.MaxInt64
)

// Block is a unit of blockchain
type Block struct {
	Timestamps int64
	Data       []byte
	PrevHash   []byte
	Hash       []byte
	None       int
}

// NewBlock create a block, set hash and return the block pointer
func NewBlock(data string, prevHash []byte) *Block {
	block := new(Block)

	block.Timestamps = time.Now().Unix()
	block.Data = []byte(data)
	block.PrevHash = prevHash

	pow := NewProofOfWork(block)
	none, hash := pow.Run()

	block.Hash = hash
	block.None = none

	return block
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
	fmt.Printf("%-12s %s\n", "Data:", block.Data)
	fmt.Printf("%-12s %s\n", "PoW:", strconv.FormatBool(isValid))
	fmt.Println()
}

// Blockchain is a array of block
type Blockchain struct {
	db  *Database
	tip []byte
}

// AddBlock is a method put a block into blockchain
func (bc *Blockchain) AddBlock(data string) {
	newBlock := NewBlock(data, bc.tip)
	bc.db.AddBlock(newBlock)
	bc.tip = newBlock.Hash
}

// NewGenesisBlock create and return the first block in blockchain
func NewGenesisBlock() *Block {
	return NewBlock("Genesis Block", []byte{})
}

// NewBlockChain create a blockchain which has a first block called Genesis block
func NewBlockChain(db *Database) *Blockchain {
	if isBlank := db.IsBlank(); isBlank {
		log.Println("DB is blank. Initialize...")

		db.InitIfBlank()
		log.Println("Init DB done. Add genesis block into DB...")

		genesis := NewGenesisBlock()
		db.AddBlock(genesis)
	}
	tip := db.GetLastHash()

	return &Blockchain{db, tip}
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
			block.Data,
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

	fmt.Printf("Mining the block containing %s\n", pow.block.Data)
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
	addBlockCmd := flag.NewFlagSet("add", flag.ExitOnError)
	printChainCmd := flag.NewFlagSet("print", flag.ExitOnError)

	addBlockData := addBlockCmd.String("data", "", "Block data")

	switch os.Args[1] {
	case "add":
		addBlockCmd.Parse(os.Args[2:])
	case "print":
		printChainCmd.Parse(os.Args[2:])
	default:
		cli.PrintUsage()
		os.Exit(0)
	}

	if addBlockCmd.Parsed() {
		if *addBlockData == "" {
			addBlockCmd.Usage()
			os.Exit(1)
		}

		cli.blockchain.AddBlock(*addBlockData)
	}

	if printChainCmd.Parsed() {
		cli.PrintChain()
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
	fmt.Printf("\t%-9s %s\n", "add", "add a block into blockchain")
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

func main() {
	db := NewDatabase()
	db.Open("blockchain.db")
	defer db.Close()

	blockchain := NewBlockChain(db)
	cli := NewCLI(blockchain)

	cli.Run()
}
