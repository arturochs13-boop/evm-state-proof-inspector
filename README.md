# evm-state-proof-inspector

Low-level Go CLI and library for EVM storage slot derivation, Merkle Patricia Trie state proof
verification, and bytecode disassembly.

No node, no RPC, no database: every command computes layout and cryptography locally so you can
check what a contract *should* have written, prove what a state root *does* commit to, and read what
compiled bytecode *actually* executes.

---

## Install and run

```bash
go build -o bin/evm-inspect ./cmd/evm-inspect
go test ./...
go vet ./...
```

Requires Go 1.22 or newer. The only dependency is `github.com/ethereum/go-ethereum`, used for its
trie, RLP, keccak, and database primitives.

```
evm-inspect
├── pkg/storage   storage slot derivation (mappings, nested mappings, arrays, structs)
├── pkg/mpt       in-memory MPT construction, inclusion proofs, independent verification
├── pkg/disasm    opcode table and linear-sweep disassembler
└── cmd/evm-inspect
```

---

## 1. Storage layout math

Solidity assigns slots at compile time. The rules are simple but easy to get subtly wrong, so the
package implements each one directly.

**Value types.** A variable declared at position `p` lives in slot `p`.

```
uint256 totalSupply;          // slot 0
address owner;                // slot 1
```

**Mappings.** An entry for key `k` in a mapping declared at `p` is stored at:

```
slot = keccak256(abi.encode(k, p))
```

Both operands are 32-byte words, so the preimage is always 64 bytes: the key word followed by the
slot word. Keys are left-padded (addresses get twelve zero bytes; `string`/`bytes` keys are hashed
first).

**Nested mappings.** Hash one level per key, folding left:

```
slot = keccak256(k2 ‖ keccak256(k1 ‖ p))
```

**Dynamic arrays.** The length lives at `p`; elements start at `keccak256(p)`:

```
element(i) = keccak256(p) + i   (mod 2^256)
```

**Structs.** A member at offset `o` of a struct based at `p` is at `p + o`; mappings and dynamic
arrays *inside* structs follow the rules above from that base.

```console
$ evm-inspect slot --base 0 --key 1
kind: mapping
base: 0x0000000000000000000000000000000000000000000000000000000000000000
key type: uint
slot: 0xada5013122d395ba3c54772283fb069b10426056ef8ca54750cb9bb552a59e7d

$ evm-inspect slot --base 0 --outer-key 1 --inner-key 2
kind: nested mapping
slot: 0xb37150ceb7e138645bfe4dfcef9a75073e1d7aa14c524dfdd20d3f751fad1084

$ evm-inspect slot --base 3 --key 0x1111111111111111111111111111111111111111 --key-type address
kind: mapping
slot: 0xfc40ea33816453f766ebc0872d4b5152b468882abe7b6b35528069db4d6e41c4

$ evm-inspect slot --base 0 --array-index 7
kind: dynamic array element
index: 7
data slot: 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563
slot: 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e6a
```

Every vector in the unit tests was generated independently with `cast keccak` over the exact
ABI-encoded preimage, so the tests pin the layout rather than re-deriving it.

---

## 2. Merkle Patricia Trie proofs

Ethereum commits to state with a Modified Merkle Patricia Trie. A proof is the set of RLP-encoded
nodes on the path from the root to a key; nodes whose encoding is shorter than 32 bytes are embedded
in their parent and never appear separately.

```
                  stateRoot (32 bytes)
                         │
                 ┌───────┴────────┐
                 │  branch node   │  children 0..f
                 └───────┬────────┘
                         │ nibble path
                 ┌───────┴────────┐
                 │ extension node │  shared prefix
                 └───────┬────────┘
                         │
                 ┌───────┴────────┐
                 │   leaf node    │  key suffix + value
                 └────────────────┘

proof = [root, …, leaf]      verify: hash each node, descend by key nibbles,
                             require the final value to match, reject any
                             node whose hash is not the one referenced.
```

The verifier never trusts the producer: it starts at the supplied 32-byte root, hashes each supplied
node, looks up the expected child hash, and fails on a missing node, wrong root, wrong key, tampered
node, or value mismatch.

```console
$ evm-inspect prove-verify
trie root: 0x3fd2dcc59f78fa767b50273a5130f1362d0e5598dfd47afcc74b08ec1c152f3e
key: account/0x2222222222222222222222222222222222222222
claimed value: balance=42,nonce=1
proof nodes: 4
  node[0] 83 bytes 0xf851…
  …
verified value: balance=42,nonce=1
verification: ok

$ evm-inspect prove-verify --tamper
…
tampered node[0] rejected as expected: mpt: proof rejected: proof node 0 (hash 3fd2…) missing
```

`--tamper-index` selects which node to flip. Because every node is content-addressed, changing one
byte changes its hash and the parent's reference no longer resolves — the proof fails closed.

Library use:

```go
tree := mpt.New()
_ = tree.Put(mpt.HashKey(account.Bytes()), accountRLP)
proof, _ := tree.Prove(mpt.HashKey(account.Bytes()))
value, err := proof.Verify()          // recomputes from proof.Root
```

Keys are raw bytes. Use `mpt.HashKey` for secure-trie semantics (state tries hash keys; storage tries
use the 32-byte slot directly).

---

## 3. Bytecode disassembly

The decoder sweeps linearly: every byte is an opcode unless it is the immediate operand of a
`PUSH1..PUSH32`. Data embedded in code after an `INVALID` opcode is still decoded as instructions,
which is what an auditor needs to see — it is also why "disassembled length" can exceed the number
of reachable instructions.

```console
$ evm-inspect disasm --code 0x6080604052348015600e575f80fd5b50
0000  0x60  PUSH1        0x80
0002  0x60  PUSH1        0x40
0004  0x52  MSTORE
0005  0x34  CALLVALUE
0006  0x80  DUP1
0007  0x15  ISZERO
0008  0x60  PUSH1        0x0e
0010  0x57  JUMPI
0011  0x5f  PUSH0
0012  0x80  DUP1
0013  0xfd  REVERT
0014  0x5b  JUMPDEST
0015  0x50  POP
-- 13 instruction(s), 16 byte(s)
```

`--file path` reads hex from disk (whitespace and an optional `0x` prefix are ignored). Truncated
push immediates return `ErrTruncatedPush` with the exact byte deficit instead of silently emitting a
short operand.

The opcode table covers Cancun-era opcodes including `PUSH0`, `TLOAD`, `TSTORE`, `MCOPY`,
`BLOBHASH`, and `BLOBBASEFEE`; unassigned bytes render as `INVALID`.

---

## Test suite

```console
$ go test ./...
ok  .../pkg/disasm
ok  .../pkg/mpt
ok  .../pkg/storage
```

**28 tests** across the three packages:

- `pkg/storage` — direct slots, mapping vectors for `uint`/`address`/`string` keys, nested mappings,
  array element arithmetic and 2^256 wrap, struct offsets, raw-key padding, address/bool encoding,
  and rejection of negative, nil, oversized, and over-wide inputs.
- `pkg/mpt` — deterministic roots, root changes on update, inclusion proofs for every key, secure-key
  namespace, tamper rejection on every node, wrong root, wrong key, value mismatch, empty proof
  handling, and `Corrupt` copy semantics.
- `pkg/disasm` — prologue decoding, state/call opcodes, `PUSH32` operands, `DUP`/`SWAP`/`LOG`
  boundaries, invalid opcodes, truncated pushes, hex parsing, and rendering.

---

## Design notes

- **Offline and deterministic.** No network calls, no hidden state; the same input always produces the
  same slot, root, or listing.
- **Independent verification.** Proof checks recompute hashes from the supplied root rather than
  trusting the tree that produced the proof.
- **Strict parsing.** Odd-length hex, empty proofs, out-of-range indices, negative values, and
  oversized keys are rejected with typed errors.
- **No globals mutated.** `Decode` allocates fresh immediates; `Corrupt` deep-copies before flipping a
  byte.
- **Small surface.** Three focused packages, one CLI, one external dependency.

---

## License

MIT
