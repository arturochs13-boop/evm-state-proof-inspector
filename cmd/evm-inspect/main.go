// Command evm-inspect exposes EVM storage layout, Merkle Patricia Trie proofs, and bytecode
// disassembly as a small offline CLI.
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/arturochs13-boop/evm-state-proof-inspector/pkg/disasm"
	"github.com/arturochs13-boop/evm-state-proof-inspector/pkg/mpt"
	"github.com/arturochs13-boop/evm-state-proof-inspector/pkg/storage"
)

const usageText = `evm-inspect — low-level EVM storage, state proof, and bytecode tooling

Usage:
  evm-inspect slot --base <slot> [--key <key> | --array-index <n> | --struct-offset <n> | --outer-key <k1> --inner-key <k2>]
  evm-inspect prove-verify [--key <key>] [--value <value>] [--tamper] [--tamper-index <n>]
  evm-inspect disasm (--code <hex> | --file <path>)

Examples:
  evm-inspect slot --base 0 --key 1
  evm-inspect slot --base 3 --key 0x1111111111111111111111111111111111111111 --key-type address
  evm-inspect slot --base 0 --outer-key 1 --inner-key 2
  evm-inspect slot --base 0 --array-index 7
  evm-inspect slot --base 0 --struct-offset 2
  evm-inspect prove-verify
  evm-inspect prove-verify --tamper
  evm-inspect disasm --code 0x6080604052348015600e575f80fd5b50
`

const (
	exitUsage = 2
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "evm-inspect: %v\n", err)

		var usageErr *usageError
		if errors.As(err, &usageErr) {
			os.Exit(exitUsage)
		}
		os.Exit(1)
	}
}

type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

func usageErrorf(format string, args ...any) error {
	return &usageError{err: fmt.Errorf(format, args...)}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usageText)
		return usageErrorf("subcommand required")
	}
	switch args[0] {
	case "slot":
		return runSlot(args[1:])
	case "prove-verify":
		return runProveVerify(args[1:])
	case "disasm":
		return runDisasm(args[1:])
	case "help", "-h", "--help":
		fmt.Print(usageText)
		return nil
	default:
		return usageErrorf("unknown subcommand %q (expected slot, prove-verify, or disasm)", args[0])
	}
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func runSlot(args []string) error {
	fs := newFlagSet("slot")
	base := fs.String("base", "0", "slot of the state variable (decimal or 0x hex)")
	key := fs.String("key", "", "mapping key")
	keyType := fs.String("key-type", "uint", "mapping key type: uint, address, string, or bool")
	outerKey := fs.String("outer-key", "", "outer key of a nested mapping")
	innerKey := fs.String("inner-key", "", "inner key of a nested mapping")
	arrayIndex := fs.String("array-index", "", "dynamic array element index")
	structOffset := fs.Uint64("struct-offset", 0, "struct member offset")
	if err := fs.Parse(args); err != nil {
		return usageErrorf("%v", err)
	}
	if fs.NArg() > 0 {
		return usageErrorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	baseSlot, err := parseSlot(*base)
	if err != nil {
		return usageErrorf("invalid --base: %v", err)
	}

	switch {
	case set["outer-key"] || set["inner-key"]:
		if !set["outer-key"] || !set["inner-key"] {
			return usageErrorf("nested mappings require both --outer-key and --inner-key")
		}
		outer, err := parseUint(*outerKey, "--outer-key")
		if err != nil {
			return usageErrorf("%v", err)
		}
		inner, err := parseUint(*innerKey, "--inner-key")
		if err != nil {
			return usageErrorf("%v", err)
		}
		outerEncoded, err := storage.EncodeUint(outer)
		if err != nil {
			return err
		}
		innerEncoded, err := storage.EncodeUint(inner)
		if err != nil {
			return err
		}
		slot := storage.NestedMappingSlot(baseSlot, outerEncoded, innerEncoded)
		fmt.Printf("kind: nested mapping\nbase: %s\nslot: %s\n", baseSlot.Hex(), slot.Hex())
		return nil

	case set["array-index"]:
		index, err := parseUint(*arrayIndex, "--array-index")
		if err != nil {
			return usageErrorf("%v", err)
		}
		slot, err := storage.ArrayElementSlot(baseSlot, index)
		if err != nil {
			return err
		}
		fmt.Printf("kind: dynamic array element\nbase: %s\nindex: %s\ndata slot: %s\nslot: %s\n",
			baseSlot.Hex(), index, storage.ArrayDataSlot(baseSlot).Hex(), slot.Hex())
		return nil

	case set["struct-offset"]:
		slot := storage.StructMemberSlot(baseSlot, *structOffset)
		fmt.Printf("kind: struct member\nbase: %s\noffset: %d\nslot: %s\n", baseSlot.Hex(), *structOffset, slot.Hex())
		return nil

	case set["key"]:
		slot, err := mappingSlot(baseSlot, *keyType, *key)
		if err != nil {
			return usageErrorf("%v", err)
		}
		fmt.Printf("kind: mapping\nbase: %s\nkey type: %s\nslot: %s\n", baseSlot.Hex(), *keyType, slot.Hex())
		return nil

	default:
		fmt.Printf("kind: direct variable\nslot: %s\n", baseSlot.Hex())
		return nil
	}
}

func mappingSlot(baseSlot common.Hash, keyType, key string) (common.Hash, error) {
	switch strings.ToLower(keyType) {
	case "uint", "uint256":
		value, err := parseUint(key, "--key")
		if err != nil {
			return common.Hash{}, err
		}
		return storage.MappingSlotUint(baseSlot, value)
	case "address":
		if !common.IsHexAddress(key) {
			return common.Hash{}, fmt.Errorf("invalid address %q", key)
		}
		return storage.MappingSlotAddress(baseSlot, common.HexToAddress(key)), nil
	case "string":
		return storage.MappingSlotString(baseSlot, key), nil
	case "bool":
		value, err := strconv.ParseBool(key)
		if err != nil {
			return common.Hash{}, fmt.Errorf("invalid bool %q", key)
		}
		return storage.MappingSlot(baseSlot, storage.EncodeBool(value)), nil
	default:
		return common.Hash{}, fmt.Errorf("unsupported --key-type %q", keyType)
	}
}

func runProveVerify(args []string) error {
	fs := newFlagSet("prove-verify")
	key := fs.String("key", "account/0x2222222222222222222222222222222222222222", "key to prove")
	value := fs.String("value", "", "expected value; defaults to the value stored in the demo trie")
	tamper := fs.Bool("tamper", false, "corrupt one proof node and show that verification fails")
	tamperIndex := fs.Int("tamper-index", 0, "proof node index to corrupt with --tamper")
	if err := fs.Parse(args); err != nil {
		return usageErrorf("%v", err)
	}
	if fs.NArg() > 0 {
		return usageErrorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	entries := map[string]string{
		"account/0x1111111111111111111111111111111111111111":   "balance=1000,nonce=7",
		"account/0x2222222222222222222222222222222222222222":   "balance=42,nonce=1",
		"account/0x3333333333333333333333333333333333333333":   "balance=0,nonce=0",
		"storage/0x1111111111111111111111111111111111111111/0": "0x0000000000000000000000000000000000000000000000000000000000000001",
		"storage/0x1111111111111111111111111111111111111111/1": "0x0000000000000000000000000000000000000000000000000000000000000002",
	}

	tree := mpt.New()
	for entryKey, entryValue := range entries {
		if err := tree.Put([]byte(entryKey), []byte(entryValue)); err != nil {
			return fmt.Errorf("inserting %q: %w", entryKey, err)
		}
	}
	root := tree.Root()

	proof, err := tree.Prove([]byte(*key))
	if err != nil {
		return fmt.Errorf("proving %q: %w", *key, err)
	}
	if *value != "" {
		proof.Value = []byte(*value)
	}

	fmt.Printf("trie root: %s\n", root.Hex())
	fmt.Printf("key: %s\n", *key)
	fmt.Printf("claimed value: %s\n", proof.Value)
	fmt.Printf("proof nodes: %d\n", len(proof.Nodes))
	for index, node := range proof.Nodes {
		fmt.Printf("  node[%d] %d bytes 0x%s\n", index, len(node), hex.EncodeToString(node))
	}

	if *tamper {
		corrupted, err := mpt.Corrupt(proof.Nodes, *tamperIndex)
		if err != nil {
			return err
		}
		tampered := &mpt.Proof{Root: proof.Root, Key: proof.Key, Value: proof.Value, Nodes: corrupted}
		if verified, err := tampered.Verify(); err == nil {
			return fmt.Errorf("tampered proof was accepted with value %q", verified)
		} else {
			fmt.Printf("tampered node[%d] rejected as expected: %v\n", *tamperIndex, err)
		}
		return nil
	}

	verified, err := proof.Verify()
	if err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}
	fmt.Printf("verified value: %s\nverification: ok\n", verified)
	return nil
}

func runDisasm(args []string) error {
	fs := newFlagSet("disasm")
	code := fs.String("code", "", "hex bytecode (0x prefix optional)")
	file := fs.String("file", "", "path to a file containing hex bytecode")
	if err := fs.Parse(args); err != nil {
		return usageErrorf("%v", err)
	}
	if fs.NArg() > 0 {
		return usageErrorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if (*code == "") == (*file == "") {
		return usageErrorf("exactly one of --code or --file is required")
	}

	input := *code
	if *file != "" {
		contents, err := os.ReadFile(*file)
		if err != nil {
			return fmt.Errorf("reading bytecode file: %w", err)
		}
		input = string(contents)
	}

	instructions, err := disasm.DecodeHex(input)
	if err != nil {
		return err
	}
	for _, instruction := range instructions {
		fmt.Println(instruction.String())
	}
	fmt.Printf("-- %d instruction(s), %d byte(s)\n", len(instructions), countBytes(instructions))
	return nil
}

func countBytes(instructions []disasm.Instruction) int {
	total := 0
	for _, instruction := range instructions {
		total += 1 + len(instruction.Immediate)
	}
	return total
}

func parseSlot(value string) (common.Hash, error) {
	parsed, err := parseUint(value, "--base")
	if err != nil {
		return common.Hash{}, err
	}
	return storage.EncodeUint(parsed)
}

func parseUint(value, label string) (*big.Int, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, fmt.Errorf("%s requires a value", label)
	}
	parsed := new(big.Int)
	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
		if _, ok := parsed.SetString(trimmed[2:], 16); !ok {
			return nil, fmt.Errorf("%s is not valid hex: %q", label, value)
		}
	} else if _, ok := parsed.SetString(trimmed, 10); !ok {
		return nil, fmt.Errorf("%s is not a valid integer: %q", label, value)
	}
	if parsed.Sign() < 0 {
		return nil, fmt.Errorf("%s must be non-negative", label)
	}
	return parsed, nil
}
