# 0014. Wire format byte-equivalence with paramant-relay

Date: 2026-05-27
Status: Accepted

## Context

`paramant-relay` has an approved wire format v1, documented in its
`docs/wire-format-v1.md` (approved 2026-04-24) and implemented in
`relay/crypto/wire-format.js` (Node, authoritative) and
`sdk-js/src/wire-format.js` (browser SDK). It is a `PQHB`-magic 10-byte header
(`MAGIC | VERSION | KEM_ID | SIG_ID | FLAGS`) followed by a length-prefixed
body, all integers big-endian. The first 10 bytes are bound into the AES-256-GCM
AAD so algorithm selection is integrity-protected.

paramant-core is the Rust replacement growing under the strangler pattern. Per
ADR-0003 (source of truth), the relay's format is canonical. An earlier draft of
this milestone proposed a *fresh* TLV format (tags, LEB128, terminator) for the
core; analysis of the relay source showed that format does not exist there and
never did  --  the relay already ships a struct-style v1. Defining a new format in
the core would have produced a blob the relay cannot decode, breaking the whole
reason the core exists.

## Decision

paramant-core's `wire.rs` MUST produce byte-identical output to
paramant-relay's `wire-format.js` for identical inputs, and MUST decode exactly
the blobs the relay produces.

1. The byte layout, big-endian encoding, header AAD, and `KEM_ID`/`SIG_ID`
   registry are transcribed from the relay spec into
   `docs/wire-format-v1.md` (a Rust-port mirror, explicitly non-authoritative).
2. KAT vectors are anchored on the two SHA-256 test vectors published in the
   relay spec (signed 5090 B  ->  `002b4f6a...`, anonymous 1778 B  ->  `46bce75b...`).
   The generator self-checks both before emitting; generated vectors cover the
   remaining algorithm IDs and boundary cases.
3. When the relay's spec evolves, paramant-core follows. Updates flow
   relay  ->  core, never the reverse. Any divergence is a paramant-core bug.

## Consequences

- **Migration path**: in M5/M6 paramant-relay can swap its `wire-format.js` for
  a `@paramant/core` NAPI binding without any client-visible byte change.
- **Test discipline**: every wire-format change must keep the relay-anchored KAT
  green in CI; the two SHA-256 anchors make a silent drift impossible.
- **Documentation hygiene**: `paramant-core/docs/wire-format-v1.md` is a mirror
  and says so; readers needing the authority go to the relay repo.
- The core's `SigId` enum tracks the relay's *runtime* registry
  (`0x0200..=0x020B` SLH-DSA), which is broader than the relay spec's table, so
  the core never rejects a blob the relay would emit.

## Alternatives

- **Define a fresh TLV format in core, port the relay later**: rejected  -- 
  violates ADR-0003 and forces a client-facing format change on an
  already-approved v1.
- **Implement only the signed path / a subset**: rejected  --  ParaShare needs
  signatures and ParaDrop/Send need the anonymous path; the full format is
  small.
- **Diverge with a version bump (core v2, relay v1)**: rejected  --  the relay is
  the live source of truth on v1; a parallel v2 fork helps no one pre-launch.
