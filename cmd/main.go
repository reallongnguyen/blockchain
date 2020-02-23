package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strconv"
	"time"
)

// Block is a unit of blockchain
type Block struct {
	Timestamps int64
	Data       []byte
	PrevHash   []byte
	Hash       []byte
	None       int
}

func (b *Block) setHash() {
	timestamp := []byte(strconv.FormatInt(b.Timestamps, 10))
	headers := bytes.Join([][]byte{b.Data, b.PrevHash, timestamp}, []byte{})

	hash := sha256.Sum256(headers)

	b.Hash = hash[:]
}

// NewBlock create a block, set hash and return the block pointer
func NewBlock(data string, prevHash []byte) *Block {
	block := new(Block)

	block.Timestamps = time.Now().Unix()
	block.Data = []byte(data)
	block.PrevHash = prevHash
	block.setHash()

	return block
}

// Blockchain is a array of block
type Blockchain struct {
	blocks []*Block
}

// AddBlock is a method put a block into blockchain
func (bc *Blockchain) AddBlock(data string) {
	prevBlock := bc.blocks[len(bc.blocks)-1]
	newBlock := NewBlock(data, prevBlock.Hash)
	bc.blocks = append(bc.blocks, newBlock)
}

// NewGenesisBlock create and return the first block in blockchain
func NewGenesisBlock() *Block {
	return NewBlock("Genesis Block", []byte{})
}

// NewBlockChain create a blockchain which has a first block called Genesis block
func NewBlockChain() *Blockchain {
	genesisBlock := NewGenesisBlock()

	return &Blockchain{[]*Block{genesisBlock}}
}

func main() {
	blockchain := NewBlockChain()
	blockchain.AddBlock("Send one <3 to Tuyen")
	blockchain.AddBlock("Send one meme to Tuyen")

	for _, block := range blockchain.blocks {
		fmt.Println("Timestamps:", time.Unix(block.Timestamps, 0))
		fmt.Printf("Hash: %x\n", block.Hash)
		fmt.Printf("Prev. hash: %x\n", block.PrevHash)
		fmt.Println("Data:", string(block.Data))
		fmt.Println()
	}
}
