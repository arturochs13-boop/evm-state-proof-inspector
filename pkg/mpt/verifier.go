// Package mpt builds in-memory Merkle Patricia Tries, generates inclusion proofs, and verifies them
// against a 32-byte root without trusting the proof producer.
//
// The trie is the same Modified Merkle Patricia Trie used by Ethereum state and storage tries: keys
// are nibble-encoded, branch nodes hold sixteen children, extension/leaf nodes compress shared
// prefixes, and any node whose RLP encoding is shorter than 32 bytes is embedded in its parent
// rather than hashed.
package mpt

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
)

// ErrEmptyValue is returned when inserting an empty value; the MPT represents absence by omitting
// the key, so an empty value is almost always a caller bug.
var ErrEmptyValue = errors.New("mpt: empty values are not stored")

// ErrNoProofNodes is returned when verification is attempted with an empty proof.
var ErrNoProofNodes = errors.New("mpt: proof contains no nodes")

// proofWriter captures the RLP-encoded nodes produced by Trie.Prove in path order.
type proofWriter struct {
	nodes [][]byte
}

func (w *proofWriter) Put(_ []byte, value []byte) error {
	w.nodes = append(w.nodes, common.CopyBytes(value))
	return nil
}

func (w *proofWriter) Delete(_ []byte) error { return nil }

// Tree is an in-memory MPT backed by a throwaway node database.
type Tree struct {
	trie *trie.Trie
}

// New returns an empty trie. Nothing is persisted; the node database lives in memory for the
// lifetime of the Tree.
func New() *Tree {
	database := triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil)
	return &Tree{trie: trie.NewEmpty(database)}
}

// Put inserts or replaces a key/value pair. Keys are raw bytes; Ethereum state tries hash keys
// before insertion (see HashKey), while storage tries use the 32-byte slot directly.
func (t *Tree) Put(key, value []byte) error {
	if len(key) == 0 {
		return errors.New("mpt: empty key")
	}
	if len(value) == 0 {
		return ErrEmptyValue
	}
	return t.trie.Update(key, value)
}

// Get returns the value stored at key.
func (t *Tree) Get(key []byte) ([]byte, error) {
	return t.trie.Get(key)
}

// Root returns the root hash of the current trie.
func (t *Tree) Root() common.Hash {
	return t.trie.Hash()
}

// HashKey returns the secure-trie key for a raw key, matching how Ethereum state tries store
// accounts (keccak256(address)) and storage slots (keccak256(slot)).
func HashKey(key []byte) []byte {
	return crypto.Keccak256(key)
}

// Proof is a self-contained inclusion proof.
type Proof struct {
	Root  common.Hash
	Key   []byte
	Value []byte
	Nodes [][]byte
}

// Prove returns the inclusion proof for key. The returned proof embeds the current root, so it can
// be verified without access to the tree.
func (t *Tree) Prove(key []byte) (*Proof, error) {
	writer := &proofWriter{}
	if err := t.trie.Prove(key, writer); err != nil {
		return nil, fmt.Errorf("mpt: generating proof: %w", err)
	}
	value, err := t.trie.Get(key)
	if err != nil {
		return nil, fmt.Errorf("mpt: reading proven value: %w", err)
	}
	if writer.nodes == nil {
		return nil, fmt.Errorf("mpt: no proof nodes for key %x", key)
	}
	return &Proof{
		Root:  t.trie.Hash(),
		Key:   common.CopyBytes(key),
		Value: common.CopyBytes(value),
		Nodes: writer.nodes,
	}, nil
}

// Verify checks the proof against its embedded root and returns the proven value.
func (p *Proof) Verify() ([]byte, error) {
	if p == nil {
		return nil, errors.New("mpt: nil proof")
	}
	value, err := VerifyProof(p.Root, p.Key, p.Nodes)
	if err != nil {
		return nil, err
	}
	if len(p.Value) > 0 && !equalBytes(value, p.Value) {
		return nil, errors.New("mpt: proof value does not match the expected value")
	}
	return value, nil
}

// VerifyProof recomputes the path from root to key using only the supplied nodes. A tampered node
// changes its hash and is rejected as a missing node; a wrong root rejects the first lookup.
func VerifyProof(root common.Hash, key []byte, nodes [][]byte) ([]byte, error) {
	if len(nodes) == 0 {
		return nil, ErrNoProofNodes
	}
	database := memorydb.New()
	for index, node := range nodes {
		if len(node) == 0 {
			return nil, fmt.Errorf("mpt: proof node %d is empty", index)
		}
		hash := crypto.Keccak256(node)
		if err := database.Put(hash, node); err != nil {
			return nil, fmt.Errorf("mpt: staging proof node %d: %w", index, err)
		}
	}

	value, err := trie.VerifyProof(root, key, database)
	if err != nil {
		return nil, fmt.Errorf("mpt: proof rejected: %w", err)
	}
	if value == nil {
		return nil, fmt.Errorf("mpt: proof does not contain key %x", key)
	}
	return value, nil
}

// EmptyRoot is the MPT root of an empty trie.
func EmptyRoot() common.Hash {
	return types.EmptyRootHash
}

// Corrupt returns a deep copy of nodes with one byte of the node at index flipped. It is used by
// the CLI's --tamper mode and by tests to demonstrate rejection.
func Corrupt(nodes [][]byte, index int) ([][]byte, error) {
	if index < 0 || index >= len(nodes) {
		return nil, fmt.Errorf("mpt: node index %d out of range [0,%d)", index, len(nodes))
	}
	corrupted := make([][]byte, len(nodes))
	for i, node := range nodes {
		corrupted[i] = common.CopyBytes(node)
	}
	target := corrupted[index]
	if len(target) == 0 {
		return nil, fmt.Errorf("mpt: node %d is empty", index)
	}
	target[len(target)-1] ^= 0xff
	return corrupted, nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
