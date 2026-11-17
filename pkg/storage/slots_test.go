package storage

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// Vectors below were produced independently with `cast keccak` over the exact ABI-encoded input,
// so they pin the layout rules rather than re-implementing them in the test.
const (
	slotMappingZeroZero  = "0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5"
	slotMappingZeroOne   = "0xada5013122d395ba3c54772283fb069b10426056ef8ca54750cb9bb552a59e7d"
	slotMappingZeroTwo   = "0xabbb5caa7dda850e60932de0934eb1f9d0f59695050f761dc64e443e5030a569"
	slotMappingThreeAddr = "0xfc40ea33816453f766ebc0872d4b5152b468882abe7b6b35528069db4d6e41c4"
	slotNested           = "0xb37150ceb7e138645bfe4dfcef9a75073e1d7aa14c524dfdd20d3f751fad1084"
	slotArrayZero        = "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
	slotMappingHello     = "0x4f46d32f55fe21019bad7ccfbcc6053d08b0d0dd058d93eb32c325caff712178"
)

var baseZero = common.Hash{}

func TestDirectSlots(t *testing.T) {
	cases := []struct {
		index uint64
		want  common.Hash
	}{
		{0, common.Hash{}},
		{1, common.HexToHash("0x01")},
		{42, common.HexToHash("0x2a")},
	}
	for _, testCase := range cases {
		slot, err := Slot(new(big.Int).SetUint64(testCase.index))
		if err != nil {
			t.Fatalf("slot %d: %v", testCase.index, err)
		}
		if slot != testCase.want {
			t.Fatalf("slot %d = %s, want %s", testCase.index, slot, testCase.want)
		}
	}
}

func TestMappingSlots(t *testing.T) {
	cases := []struct {
		name string
		got  common.Hash
		want string
	}{
		{"mapping(uint256=>v) slot 0 key 0", MappingSlot(baseZero, EncodeUintOrPanic(0)), slotMappingZeroZero},
		{"mapping(uint256=>v) slot 0 key 1", MappingSlot(baseZero, EncodeUintOrPanic(1)), slotMappingZeroOne},
		{"mapping(uint256=>v) slot 0 key 2", MappingSlot(baseZero, EncodeUintOrPanic(2)), slotMappingZeroTwo},
		{
			"mapping(address=>v) slot 3 key 0x11…11",
			MappingSlotAddress(common.HexToHash("0x03"), common.HexToAddress("0x1111111111111111111111111111111111111111")),
			slotMappingThreeAddr,
		},
		{"mapping(string=>v) slot 0 key hello", MappingSlotString(baseZero, "hello"), slotMappingHello},
	}
	for _, testCase := range cases {
		if got := testCase.got.Hex(); got != testCase.want {
			t.Fatalf("%s = %s, want %s", testCase.name, got, testCase.want)
		}
	}
}

func TestNestedMappingSlot(t *testing.T) {
	// mapping(uint256 => mapping(uint256 => uint256)) at slot 0, keys (1, 2).
	got := NestedMappingSlot(baseZero, EncodeUintOrPanic(1), EncodeUintOrPanic(2))
	if got.Hex() != slotNested {
		t.Fatalf("nested slot = %s, want %s", got.Hex(), slotNested)
	}
}

func TestArraySlots(t *testing.T) {
	if got := ArrayDataSlot(baseZero).Hex(); got != slotArrayZero {
		t.Fatalf("array data slot = %s, want %s", got, slotArrayZero)
	}

	dataSlot := ArrayDataSlot(baseZero)
	start := new(big.Int).SetBytes(dataSlot[:])
	for _, index := range []uint64{0, 1, 7, 255} {
		slot, err := ArrayElementSlot(baseZero, new(big.Int).SetUint64(index))
		if err != nil {
			t.Fatalf("array index %d: %v", index, err)
		}
		want := new(big.Int).Add(start, new(big.Int).SetUint64(index))
		if slot != common.BytesToHash(want.Bytes()) {
			t.Fatalf("array index %d = %s, want %x", index, slot, want)
		}
	}

	// Element slots wrap at 2^256: pick the index that lands exactly on zero.
	index := new(big.Int).Sub(twoTo256, start)
	slot, err := ArrayElementSlot(baseZero, index)
	if err != nil {
		t.Fatalf("wrapping array slot: %v", err)
	}
	if slot != (common.Hash{}) {
		t.Fatalf("wrapped array slot = %s, want zero", slot)
	}
}

func TestStructMemberSlot(t *testing.T) {
	base := common.HexToHash("0x10")
	if got := StructMemberSlot(base, 2); got != common.HexToHash("0x12") {
		t.Fatalf("struct member slot = %s, want 0x12", got)
	}
	if got := StructMemberSlot(common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), 1); got != (common.Hash{}) {
		t.Fatalf("wrapping struct member slot = %s, want zero", got)
	}
}

func TestRawMappingKeys(t *testing.T) {
	short, err := MappingSlotRaw(baseZero, []byte{0x01})
	if err != nil {
		t.Fatalf("short key: %v", err)
	}
	if short != MappingSlot(baseZero, common.HexToHash("0x01")) {
		t.Fatal("short key was not left-padded")
	}

	long := make([]byte, 33)
	if _, err := MappingSlotRaw(baseZero, long); !errors.Is(err, ErrKeyTooLong) {
		t.Fatalf("33-byte key: got %v, want ErrKeyTooLong", err)
	}
}

func TestEncodingValidation(t *testing.T) {
	if _, err := EncodeUint(nil); !errors.Is(err, ErrNilValue) {
		t.Fatalf("nil: got %v, want ErrNilValue", err)
	}
	if _, err := EncodeUint(big.NewInt(-1)); !errors.Is(err, ErrNegativeValue) {
		t.Fatalf("negative: got %v, want ErrNegativeValue", err)
	}
	tooLarge := new(big.Int).Lsh(big.NewInt(1), 256)
	if _, err := EncodeUint(tooLarge); err == nil {
		t.Fatal("accepted a value wider than uint256")
	}
	if _, err := ArrayElementSlot(baseZero, big.NewInt(-1)); !errors.Is(err, ErrNegativeValue) {
		t.Fatalf("negative array index: got %v, want ErrNegativeValue", err)
	}
	if _, err := ArrayElementSlot(baseZero, nil); !errors.Is(err, ErrNilValue) {
		t.Fatalf("nil array index: got %v, want ErrNilValue", err)
	}
}

func TestEncodeAddressAndBool(t *testing.T) {
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	word := EncodeAddress(addr)
	if common.BytesToAddress(word[12:]) != addr {
		t.Fatal("address encoding lost bytes")
	}
	for i := 0; i < 12; i++ {
		if word[i] != 0 {
			t.Fatal("address padding is not zero")
		}
	}
	if EncodeBool(true) != common.HexToHash("0x01") || EncodeBool(false) != (common.Hash{}) {
		t.Fatal("bool encoding is not 0/1")
	}
}

func EncodeUintOrPanic(value uint64) common.Hash {
	encoded, err := EncodeUint(new(big.Int).SetUint64(value))
	if err != nil {
		panic(err)
	}
	return encoded
}
