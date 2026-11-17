package disasm

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestDecodeSimplePrologue(t *testing.T) {
	instructions, err := DecodeHex("0x6080604052")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(instructions) != 3 {
		t.Fatalf("got %d instructions, want 3", len(instructions))
	}

	first := instructions[0]
	if first.PC != 0 || first.Name != "PUSH1" || hex.EncodeToString(first.Immediate) != "80" {
		t.Fatalf("first instruction = %+v", first)
	}
	second := instructions[1]
	if second.PC != 2 || second.Name != "PUSH1" || hex.EncodeToString(second.Immediate) != "40" {
		t.Fatalf("second instruction = %+v", second)
	}
	third := instructions[2]
	if third.PC != 4 || third.Name != "MSTORE" || len(third.Immediate) != 0 {
		t.Fatalf("third instruction = %+v", third)
	}
}

func TestDecodeStateAndCallOpcodes(t *testing.T) {
	cases := []struct {
		bytecode string
		want     []string
	}{
		{"600054", []string{"PUSH1", "SLOAD"}},
		{"6001600055", []string{"PUSH1", "PUSH1", "SSTORE"}},
		{"34", []string{"CALLVALUE"}},
		{"801561000a57", []string{"DUP1", "ISZERO", "PUSH2", "JUMPI"}},
		{"600035600052", []string{"PUSH1", "CALLDATALOAD", "PUSH1", "MSTORE"}},
		{"5f80fd", []string{"PUSH0", "DUP1", "REVERT"}},
		{"600060006000600060006000f4", []string{"PUSH1", "PUSH1", "PUSH1", "PUSH1", "PUSH1", "PUSH1", "DELEGATECALL"}},
		{"a0a1a2a3a4", []string{"LOG0", "LOG1", "LOG2", "LOG3", "LOG4"}},
		{"600160026003600460056006600760086009600a600b600c600d600e600f60106011", []string{
			"PUSH1", "PUSH1", "PUSH1", "PUSH1", "PUSH1", "PUSH1", "PUSH1", "PUSH1",
			"PUSH1", "PUSH1", "PUSH1", "PUSH1", "PUSH1", "PUSH1", "PUSH1", "PUSH1", "PUSH1",
		}},
	}

	for _, testCase := range cases {
		instructions, err := DecodeHex(testCase.bytecode)
		if err != nil {
			t.Fatalf("decode %q: %v", testCase.bytecode, err)
		}
		if len(instructions) != len(testCase.want) {
			t.Fatalf("decode %q: got %d instructions, want %d", testCase.bytecode, len(instructions), len(testCase.want))
		}
		for index, want := range testCase.want {
			if instructions[index].Name != want {
				t.Fatalf("decode %q: instruction %d = %s, want %s", testCase.bytecode, index, instructions[index].Name, want)
			}
		}
	}
}

func TestDecodePush32Operand(t *testing.T) {
	payload := strings.Repeat("ab", 32)
	instructions, err := DecodeHex("7f" + payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(instructions) != 1 {
		t.Fatalf("got %d instructions, want 1", len(instructions))
	}
	if instructions[0].Name != "PUSH32" {
		t.Fatalf("name = %s", instructions[0].Name)
	}
	if got := hex.EncodeToString(instructions[0].Immediate); got != payload {
		t.Fatalf("immediate = %s, want %s", got, payload)
	}
}

func TestDecodeDupSwapBoundaries(t *testing.T) {
	for opcode, want := range map[byte]string{0x80: "DUP1", 0x8f: "DUP16", 0x90: "SWAP1", 0x9f: "SWAP16"} {
		instructions, err := Decode([]byte{opcode})
		if err != nil {
			t.Fatalf("decode 0x%02x: %v", opcode, err)
		}
		if instructions[0].Name != want {
			t.Fatalf("opcode 0x%02x = %s, want %s", opcode, instructions[0].Name, want)
		}
	}
}

func TestDecodeInvalidOpcodes(t *testing.T) {
	for _, opcode := range []byte{0x0c, 0x0f, 0x21, 0x4b, 0xa5, 0xf6, 0xfb, 0xfe} {
		instructions, err := Decode([]byte{opcode})
		if err != nil {
			t.Fatalf("decode 0x%02x: %v", opcode, err)
		}
		if instructions[0].Name != "INVALID" {
			t.Fatalf("opcode 0x%02x = %s, want INVALID", opcode, instructions[0].Name)
		}
	}
}

func TestDecodeTruncatedPush(t *testing.T) {
	cases := []string{"60", "6100", "7f" + strings.Repeat("11", 31)}
	for _, bytecode := range cases {
		_, err := DecodeHex(bytecode)
		if !errors.Is(err, ErrTruncatedPush) {
			t.Fatalf("decode %q: got %v, want ErrTruncatedPush", bytecode, err)
		}
	}
}

func TestParseHexValidation(t *testing.T) {
	cases := []string{"", "0x", "123", "zz"}
	for _, input := range cases {
		if _, err := ParseHex(input); err == nil {
			t.Fatalf("accepted invalid hex %q", input)
		}
	}

	decoded, err := ParseHex("0X60 80\n60 40")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if hex.EncodeToString(decoded) != "60806040" {
		t.Fatalf("parsed %x", decoded)
	}
}

func TestInstructionString(t *testing.T) {
	instructions, err := DecodeHex("6080604052")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := instructions[0].String(); !strings.Contains(got, "PUSH1") || !strings.Contains(got, "0x80") {
		t.Fatalf("rendered %q", got)
	}
	if got := instructions[2].String(); !strings.Contains(got, "MSTORE") {
		t.Fatalf("rendered %q", got)
	}
}

func TestEmptyBytecode(t *testing.T) {
	instructions, err := Decode(nil)
	if err != nil {
		t.Fatalf("decode nil: %v", err)
	}
	if len(instructions) != 0 {
		t.Fatalf("got %d instructions for empty bytecode", len(instructions))
	}
}
