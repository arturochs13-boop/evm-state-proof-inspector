// Package disasm translates raw EVM bytecode into opcode listings with program counters and push
// operands.
//
// The decoder is a linear sweep: every byte is an opcode except the immediate bytes that follow a
// PUSH1..PUSH32. This matches how the EVM itself walks code, so data embedded after an INVALID
// opcode is still decoded as opcodes, which is exactly what a bytecode auditor needs to see.
package disasm

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrTruncatedPush is returned when bytecode ends inside a push immediate.
var ErrTruncatedPush = errors.New("disasm: truncated push immediate")

var opcodeNames = buildTable()

func buildTable() [256]string {
	var names [256]string
	for index := range names {
		names[index] = "INVALID"
	}

	named := map[byte]string{
		0x00: "STOP",
		0x01: "ADD",
		0x02: "MUL",
		0x03: "SUB",
		0x04: "DIV",
		0x05: "SDIV",
		0x06: "MOD",
		0x07: "SMOD",
		0x08: "ADDMOD",
		0x09: "MULMOD",
		0x0a: "EXP",
		0x0b: "SIGNEXTEND",
		0x10: "LT",
		0x11: "GT",
		0x12: "SLT",
		0x13: "SGT",
		0x14: "EQ",
		0x15: "ISZERO",
		0x16: "AND",
		0x17: "OR",
		0x18: "XOR",
		0x19: "NOT",
		0x1a: "BYTE",
		0x1b: "SHL",
		0x1c: "SHR",
		0x1d: "SAR",
		0x20: "KECCAK256",
		0x30: "ADDRESS",
		0x31: "BALANCE",
		0x32: "ORIGIN",
		0x33: "CALLER",
		0x34: "CALLVALUE",
		0x35: "CALLDATALOAD",
		0x36: "CALLDATASIZE",
		0x37: "CALLDATACOPY",
		0x38: "CODESIZE",
		0x39: "CODECOPY",
		0x3a: "GASPRICE",
		0x3b: "EXTCODESIZE",
		0x3c: "EXTCODECOPY",
		0x3d: "RETURNDATASIZE",
		0x3e: "RETURNDATACOPY",
		0x3f: "EXTCODEHASH",
		0x40: "BLOCKHASH",
		0x41: "COINBASE",
		0x42: "TIMESTAMP",
		0x43: "NUMBER",
		0x44: "PREVRANDAO",
		0x45: "GASLIMIT",
		0x46: "CHAINID",
		0x47: "SELFBALANCE",
		0x48: "BASEFEE",
		0x49: "BLOBHASH",
		0x4a: "BLOBBASEFEE",
		0x50: "POP",
		0x51: "MLOAD",
		0x52: "MSTORE",
		0x53: "MSTORE8",
		0x54: "SLOAD",
		0x55: "SSTORE",
		0x56: "JUMP",
		0x57: "JUMPI",
		0x58: "PC",
		0x59: "MSIZE",
		0x5a: "GAS",
		0x5b: "JUMPDEST",
		0x5c: "TLOAD",
		0x5d: "TSTORE",
		0x5e: "MCOPY",
		0x5f: "PUSH0",
		0xf0: "CREATE",
		0xf1: "CALL",
		0xf2: "CALLCODE",
		0xf3: "RETURN",
		0xf4: "DELEGATECALL",
		0xf5: "CREATE2",
		0xfa: "STATICCALL",
		0xfd: "REVERT",
		0xff: "SELFDESTRUCT",
	}
	for opcode, name := range named {
		names[opcode] = name
	}
	for index := 0; index < 32; index++ {
		names[0x60+index] = fmt.Sprintf("PUSH%d", index+1)
	}
	for index := 0; index < 16; index++ {
		names[0x80+index] = fmt.Sprintf("DUP%d", index+1)
		names[0x90+index] = fmt.Sprintf("SWAP%d", index+1)
	}
	for index := 0; index < 5; index++ {
		names[0xa0+index] = fmt.Sprintf("LOG%d", index)
	}

	return names
}

// Name returns the mnemonic for an opcode byte. Unassigned bytes report INVALID.
func Name(opcode byte) string {
	return opcodeNames[opcode]
}

// PushWidth reports how many immediate bytes follow an opcode.
func PushWidth(opcode byte) (int, bool) {
	if opcode >= 0x60 && opcode <= 0x7f {
		return int(opcode - 0x5f), true
	}
	return 0, false
}

// Instruction is one decoded opcode.
type Instruction struct {
	PC        uint64
	Opcode    byte
	Name      string
	Immediate []byte
}

// String renders an instruction as `pc  OPCODE  0ximmediate`.
func (i Instruction) String() string {
	if len(i.Immediate) == 0 {
		return fmt.Sprintf("%04d  0x%02x  %s", i.PC, i.Opcode, i.Name)
	}
	return fmt.Sprintf("%04d  0x%02x  %-12s 0x%s", i.PC, i.Opcode, i.Name, hex.EncodeToString(i.Immediate))
}

// Decode disassembles bytecode. It stops with ErrTruncatedPush if a push immediate runs past the
// end of the input.
func Decode(code []byte) ([]Instruction, error) {
	instructions := make([]Instruction, 0, len(code)/2+1)
	for pc := 0; pc < len(code); {
		opcode := code[pc]
		width, isPush := PushWidth(opcode)
		if !isPush {
			instructions = append(instructions, Instruction{
				PC:     uint64(pc),
				Opcode: opcode,
				Name:   Name(opcode),
			})
			pc++
			continue
		}

		available := len(code) - pc - 1
		if available < width {
			return nil, fmt.Errorf("%w: PUSH%d at pc %d needs %d byte(s), have %d",
				ErrTruncatedPush, width, pc, width, available)
		}
		immediate := make([]byte, width)
		copy(immediate, code[pc+1:pc+1+width])
		instructions = append(instructions, Instruction{
			PC:        uint64(pc),
			Opcode:    opcode,
			Name:      Name(opcode),
			Immediate: immediate,
		})
		pc += 1 + width
	}
	return instructions, nil
}

// DecodeHex accepts optional `0x` prefix and whitespace, then delegates to Decode.
func DecodeHex(input string) ([]Instruction, error) {
	code, err := ParseHex(input)
	if err != nil {
		return nil, err
	}
	return Decode(code)
}

// ParseHex parses hex bytecode with an optional 0x prefix, ignoring whitespace.
func ParseHex(input string) ([]byte, error) {
	cleaned := strings.NewReplacer(" ", "", "\n", "", "\r", "", "\t", "").Replace(input)
	cleaned = strings.TrimPrefix(strings.TrimPrefix(cleaned, "0x"), "0X")
	if cleaned == "" {
		return nil, errors.New("disasm: empty bytecode")
	}
	if len(cleaned)%2 != 0 {
		return nil, fmt.Errorf("disasm: odd-length hex string (%d nibbles)", len(cleaned))
	}
	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("disasm: invalid hex: %w", err)
	}
	return decoded, nil
}
