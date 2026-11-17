package mpt

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func testEntries() map[string]string {
	return map[string]string{
		"account/0x1111111111111111111111111111111111111111":   "balance=1000,nonce=7",
		"account/0x2222222222222222222222222222222222222222":   "balance=42,nonce=1",
		"account/0x3333333333333333333333333333333333333333":   "balance=0,nonce=0",
		"storage/0x1111111111111111111111111111111111111111/0": "0x0000000000000000000000000000000000000000000000000000000000000001",
		"storage/0x1111111111111111111111111111111111111111/1": "0x0000000000000000000000000000000000000000000000000000000000000002",
	}
}

func buildTree(t *testing.T) (*Tree, map[string]string) {
	t.Helper()
	tree := New()
	entries := testEntries()
	for key, value := range entries {
		if err := tree.Put([]byte(key), []byte(value)); err != nil {
			t.Fatalf("put %q: %v", key, err)
		}
	}
	return tree, entries
}

func TestRootIsDeterministic(t *testing.T) {
	first, _ := buildTree(t)
	second, _ := buildTree(t)
	if first.Root() != second.Root() {
		t.Fatalf("roots differ: %s != %s", first.Root(), second.Root())
	}
	if first.Root() == EmptyRoot() {
		t.Fatal("non-empty trie returned the empty root")
	}
}

func TestRootChangesWithValue(t *testing.T) {
	tree, _ := buildTree(t)
	before := tree.Root()
	if err := tree.Put([]byte("account/0x1111111111111111111111111111111111111111"), []byte("balance=9999,nonce=7")); err != nil {
		t.Fatalf("update: %v", err)
	}
	if tree.Root() == before {
		t.Fatal("root did not change after a value update")
	}
}

func TestProveAndVerifyEveryKey(t *testing.T) {
	tree, entries := buildTree(t)

	for key, want := range entries {
		proof, err := tree.Prove([]byte(key))
		if err != nil {
			t.Fatalf("prove %q: %v", key, err)
		}
		if proof.Root != tree.Root() {
			t.Fatalf("proof root %s does not match tree root %s", proof.Root, tree.Root())
		}
		value, err := proof.Verify()
		if err != nil {
			t.Fatalf("verify %q: %v", key, err)
		}
		if string(value) != want {
			t.Fatalf("verified value for %q = %q, want %q", key, value, want)
		}
	}
}

func TestProofsShareASecureKeyNamespace(t *testing.T) {
	tree := New()
	key := []byte("account/0x1111111111111111111111111111111111111111")
	hashed := HashKey(key)
	if err := tree.Put(hashed, []byte("secure-value")); err != nil {
		t.Fatalf("put hashed key: %v", err)
	}

	proof, err := tree.Prove(hashed)
	if err != nil {
		t.Fatalf("prove hashed key: %v", err)
	}
	value, err := proof.Verify()
	if err != nil {
		t.Fatalf("verify hashed key: %v", err)
	}
	if string(value) != "secure-value" {
		t.Fatalf("value = %q", value)
	}

	if _, err := tree.Prove(key); err != nil {
		t.Fatalf("proving the unhashed key should still return an absence proof: %v", err)
	}
}

func TestProofRejectsTamperedNodes(t *testing.T) {
	tree, _ := buildTree(t)
	key := []byte("account/0x2222222222222222222222222222222222222222")
	proof, err := tree.Prove(key)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if len(proof.Nodes) < 2 {
		t.Fatalf("expected a multi-node proof, got %d node(s)", len(proof.Nodes))
	}

	for index := range proof.Nodes {
		corrupted, err := Corrupt(proof.Nodes, index)
		if err != nil {
			t.Fatalf("corrupt %d: %v", index, err)
		}
		tampered := &Proof{Root: proof.Root, Key: proof.Key, Nodes: corrupted}
		value, err := tampered.Verify()
		if err == nil {
			t.Fatalf("tampered node %d was accepted with value %q", index, value)
		}
	}
}

func TestProofRejectsWrongRoot(t *testing.T) {
	tree, _ := buildTree(t)
	proof, err := tree.Prove([]byte("account/0x3333333333333333333333333333333333333333"))
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	proof.Root = common.HexToHash("0xdeadbeef")
	if _, err := proof.Verify(); err == nil {
		t.Fatal("proof verified against a wrong root")
	}
}

func TestProofRejectsWrongKey(t *testing.T) {
	tree, _ := buildTree(t)
	proof, err := tree.Prove([]byte("account/0x1111111111111111111111111111111111111111"))
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	proof.Key = []byte("account/0x9999999999999999999999999999999999999999")
	value, err := proof.Verify()
	if err == nil && bytes.Equal(value, proof.Value) {
		t.Fatal("proof for one key verified a different key")
	}
}

func TestProofValueMismatchIsRejected(t *testing.T) {
	tree, _ := buildTree(t)
	proof, err := tree.Prove([]byte("account/0x1111111111111111111111111111111111111111"))
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	proof.Value = []byte("balance=666666,nonce=7")
	if _, err := proof.Verify(); err == nil {
		t.Fatal("proof with a mismatched expected value was accepted")
	}
}

func TestCorruptValidatesIndexAndCopies(t *testing.T) {
	nodes := [][]byte{{0x01, 0x02}, {0x03}}
	if _, err := Corrupt(nodes, -1); err == nil {
		t.Fatal("accepted a negative index")
	}
	if _, err := Corrupt(nodes, 2); err == nil {
		t.Fatal("accepted an out-of-range index")
	}

	corrupted, err := Corrupt(nodes, 0)
	if err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if nodes[0][1] != 0x02 {
		t.Fatal("Corrupt mutated the input slice")
	}
	if corrupted[0][1] == nodes[0][1] {
		t.Fatal("Corrupt did not flip a byte")
	}
}

func TestVerifyRejectsEmptyProof(t *testing.T) {
	if _, err := VerifyProof(common.Hash{}, []byte("key"), nil); !errors.Is(err, ErrNoProofNodes) {
		t.Fatalf("empty proof: got %v, want ErrNoProofNodes", err)
	}
	if _, err := VerifyProof(common.Hash{}, []byte("key"), [][]byte{{}}); err == nil {
		t.Fatal("accepted an empty node")
	}
}

func TestPutRejectsEmptyInputs(t *testing.T) {
	tree := New()
	if err := tree.Put(nil, []byte("value")); err == nil {
		t.Fatal("accepted an empty key")
	}
	if err := tree.Put([]byte("key"), nil); !errors.Is(err, ErrEmptyValue) {
		t.Fatalf("empty value: got %v, want ErrEmptyValue", err)
	}
}
