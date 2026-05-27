# 0004. Code minimization (design principle D)

Datum: 2026-05-26
Status: Geaccepteerd

## Context

Less code is less audit surface, fewer bugs, less cognitive load  --  and this code
goes to a paid external audit. Unchecked, Rust projects accrete traits, generics,
helper modules, and speculative abstraction. We decide against that up front.

## Beslissing

**Maximum effect, minimum surface.** Concretely:

- One file per module unless it exceeds ~300 lines (then split, e.g.
  `kem.rs`  ->  `kem/mod.rs` + `kem/hybrid.rs`)  --  never preemptively.
- Use vetted crates for crypto primitives; do not reimplement.
- Re-export where wrapping adds nothing; wrap only for security (`Secret<T>`).
- Functions over builders where a function fits.
- 2 crates at M0, not 6. Add a crate only at the milestone that needs it.
- ~2000 lines of Rust for the whole core is the target, not a coincidence.

**Anti-patterns we do not do:**

- No `<T: Trait + Send + Sync + 'static>` where concrete types suffice.
- No traits without two or more implementations.
- No generics without a clear reason.
- No macros that hide magic.
- No helper-helper-helper module towers.
- No "future-proofing" for scenarios we cannot name.

## Consequenties

- Reviewers and auditors read less and understand faster.
- Some changes feel "manual" rather than abstracted  --  accepted on purpose.
- A new abstraction must justify itself in the PR; on a security path it needs
  an ADR.

## Alternatieven

- **Idiomatic-maximalist Rust** (traits + generics everywhere): rejected  --  more
  surface, slower audit, no payoff at this size.
- **Premature multi-crate split**: rejected  --  crates arrive with the milestone
  that needs them (blueprint Sec.2 table).
