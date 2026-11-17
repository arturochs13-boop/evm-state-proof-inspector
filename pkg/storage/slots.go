// Package storage derives EVM storage slots exactly as the Solidity compiler lays them out.
//
// The rules this package implements:
//
//   - A value-type state variable at position p occupies slot p.
//   - A mapping declared at p stores its entries at keccak256(abi.encode(key, p)).
//   - A nested mapping hashes one level per key, folding left:
//     keccak256(k2 || keccak256(k1 || p)).
//   - A dynamic array declared at p stores its length at p and its elements starting at
//     keccak256(p) + i (mod 2^256).
//   - A struct member at offset o of a struct based at p lives at p + o.
//   - A mapping with a string key hashes the key first:
//     keccak256(keccak256(key) || p).
//
// All keys are ABI-encoded as 32-byte words: value types are left-padded, addresses are padded on
// the left with twelve zero bytes, and bytes32 values are used as-is.
package storage

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// ErrNegativeValue is returned for values that cannot be represented as uint256.
var ErrNegativeValue = errors.New("storage: negative value cannot be encoded as uint256")

// ErrKeyTooLong is returned when a raw mapping key does not fit into one 32-byte word.
var ErrKeyTooLong = errors.New("storage: mapping key exceeds 32 bytes")

// ErrNilValue is returned when a required numeric argument is nil.
var ErrNilValue = errors.New("storage: nil value")

var twoTo256 = new(big.Int).Lsh(big.NewInt(1), 256)

// Slot returns the storage slot of a value-type variable at position `index`.
func Slot(index *big.Int) (common.Hash, error) {
	return EncodeUint(index)
}

// EncodeUint left-pads a uint256 into a 32-byte word.
func EncodeUint(value *big.Int) (common.Hash, error) {
	if value == nil {
		return common.Hash{}, ErrNilValue
	}
	if value.Sign() < 0 {
		return common.Hash{}, ErrNegativeValue
	}
	if value.BitLen() > 256 {
		return common.Hash{}, fmt.Errorf("storage: value exceeds uint256: %s", value)
	}
	return common.BytesToHash(value.FillBytes(make([]byte, 32))), nil
}

// EncodeAddress returns the 32-byte word for an address key.
func EncodeAddress(address common.Address) common.Hash {
	var word common.Hash
	copy(word[12:], address[:])
	return word
}

// EncodeBool returns the 32-byte word for a bool key.
func EncodeBool(value bool) common.Hash {
	if value {
		return common.BytesToHash([]byte{1})
	}
	return common.Hash{}
}

// EncodeBytes32 returns the word for a bytes32 key.
func EncodeBytes32(value [32]byte) common.Hash {
	return value
}

// MappingSlot returns the slot of `mapping(keyType => value)` at baseSlot for an already encoded
// 32-byte key: keccak256(key || baseSlot).
func MappingSlot(baseSlot common.Hash, encodedKey common.Hash) common.Hash {
	var buffer [64]byte
	copy(buffer[:32], encodedKey[:])
	copy(buffer[32:], baseSlot[:])
	return crypto.Keccak256Hash(buffer[:])
}

// MappingSlotRaw left-pads a key of at most 32 bytes and hashes it with the base slot.
func MappingSlotRaw(baseSlot common.Hash, key []byte) (common.Hash, error) {
	if len(key) > 32 {
		return common.Hash{}, ErrKeyTooLong
	}
	var word common.Hash
	copy(word[32-len(key):], key)
	return MappingSlot(baseSlot, word), nil
}

// MappingSlotUint derives a mapping slot for an unsigned integer key.
func MappingSlotUint(baseSlot common.Hash, key *big.Int) (common.Hash, error) {
	encoded, err := EncodeUint(key)
	if err != nil {
		return common.Hash{}, err
	}
	return MappingSlot(baseSlot, encoded), nil
}

// MappingSlotAddress derives a mapping slot for an address key.
func MappingSlotAddress(baseSlot common.Hash, key common.Address) common.Hash {
	return MappingSlot(baseSlot, EncodeAddress(key))
}

// MappingSlotString derives a mapping slot for a string key. Solidity hashes dynamic keys before
// hashing them with the slot: keccak256(keccak256(key) || baseSlot).
func MappingSlotString(baseSlot common.Hash, key string) common.Hash {
	keyHash := crypto.Keccak256Hash([]byte(key))
	return MappingSlot(baseSlot, keyHash)
}

// NestedMappingSlot folds one hash per key over the base slot. The first key is the outermost
// mapping and the last key is the innermost.
func NestedMappingSlot(baseSlot common.Hash, encodedKeys ...common.Hash) common.Hash {
	slot := baseSlot
	for _, key := range encodedKeys {
		slot = MappingSlot(slot, key)
	}
	return slot
}

// ArrayDataSlot returns the slot of element zero of a dynamic array declared at baseSlot:
// keccak256(baseSlot).
func ArrayDataSlot(baseSlot common.Hash) common.Hash {
	return crypto.Keccak256Hash(baseSlot[:])
}

// ArrayElementSlot returns keccak256(baseSlot) + index (mod 2^256).
func ArrayElementSlot(baseSlot common.Hash, index *big.Int) (common.Hash, error) {
	if index == nil {
		return common.Hash{}, ErrNilValue
	}
	if index.Sign() < 0 {
		return common.Hash{}, ErrNegativeValue
	}
	dataSlot := ArrayDataSlot(baseSlot)
	start := new(big.Int).SetBytes(dataSlot[:])
	sum := new(big.Int).Add(start, index)
	sum.Mod(sum, twoTo256)
	return common.BytesToHash(sum.FillBytes(make([]byte, 32))), nil
}

// StructMemberSlot returns baseSlot + offset (mod 2^256).
func StructMemberSlot(baseSlot common.Hash, offset uint64) common.Hash {
	base := new(big.Int).SetBytes(baseSlot[:])
	sum := new(big.Int).Add(base, new(big.Int).SetUint64(offset))
	sum.Mod(sum, twoTo256)
	return common.BytesToHash(sum.FillBytes(make([]byte, 32)))
}
