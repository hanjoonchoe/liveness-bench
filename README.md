# liveness-bench

Benchmarks for **agent liveness/freshness verification** — the "is this registered
agent actually alive *right now*, verifiably?" problem behind `active: true` in
ERC-8004-style registries. Each scheme answers the same question but pays a very
different per-gating cost. We measure the **consumer's per-gating verify path**, since
that is what multiplies by the number of gating decisions.

Run:

```
cargo run --release --example report   # proof / root sizes + verify shape
cargo bench                            # criterion verify-time measurements
```

## Schemes

| # | scheme | idea | trust assumption |
|---|--------|------|------------------|
| 1 | `naive-per-call` | each agent self-signs its liveness; no shared root | self-report + re-probe |
| 2 | `merkle-ct` | one signed Merkle root commits all N; `O(log N)` inclusion proof | cryptographic |
| 3 | `sig-attestation` | a third-party attestor signs each agent once per window; consumer caches | honest attestor |
| 4 | `rsa-accumulator` | one constant-size accumulator; `O(1)`-in-N membership witness | cryptographic |
| 5 | `crypto-economic-bond` | no proof — liveness backed by stake, slashed on failure; consumer reads on-chain status | economic + honest watchtower |
| — | `kzg-verkle` *(literature proxy)* | vector commitment, constant-size proof | cryptographic |
| — | `recursive-snark` *(literature proxy)* | N proofs folded into one succinct proof | cryptographic |

## Results

**Machine:** local (Apple Silicon), `cargo bench` (criterion), release. Medians.

### Per-gating verify cost (N = 1000)

| scheme | verify (median) | proof bytes | root/window | notes |
|--------|----------------:|------------:|------------:|-------|
| `crypto-economic-bond` | **4.3 ns** | 0 | 32 B | O(1) state lookup, **0 network round-trips** |
| `merkle-ct` | **2.28 µs** | 330 B | 32 B | ~log₂N SHA-256 hashes |
| `sig-attestation` | **17.1 µs** | 64 B | 32 B | 1 Ed25519 verify (cached over window) |
| `naive-per-call` | **17.0 µs** | 64 B | 0 | 1 Ed25519 verify, but **no shared root → fetch N** |
| `rsa-accumulator` | **74.9 µs** | 256 B | 256 B | 1 modexp — O(1) in N, but a **big** constant |
| `kzg-verkle` *(proxy)* | ~1–2 ms | ~48 B | 48 B | one pairing; smallest proof |
| `recursive-snark` *(proxy)* | ~2–10 ms | ~200 B–1 KB | ~200 B | O(1) in N; folds N into one |

### Scaling with N (verify median)

| scheme | N=100 | N=1 000 | N=10 000 | N=100 000 | shape |
|--------|------:|--------:|---------:|----------:|-------|
| `crypto-economic-bond` | 4.4 ns | 4.3 ns | 4.2 ns | 4.4 ns | **flat — O(1)** |
| `sig-attestation` | 17.0 µs | 17.1 µs | 17.1 µs | 16.4 µs | **flat — O(1)** |
| `merkle-ct` | 1.69 µs | 2.22 µs | 3.27 µs | 3.94 µs | **~log N** |

## What the numbers say (that big-O hides)

1. **`O(1)` is not automatically the winner — the constant matters.** The RSA
   accumulator is `O(1)` in N, yet at 75 µs it is **~33× slower than Merkle's `O(log N)`**
   (2.3 µs) at N=1000. For Merkle's log-term to even reach 75 µs, N would have to be
   astronomically large. In practice **Merkle is the sweet spot** for cryptographic
   proofs at realistic registry sizes.

2. **Merkle scaling is gentle.** 100 → 100 000 agents (1000×) only moved verify from
   1.7 µs to 3.9 µs — the log term adds a few sibling hashes, nothing more.

3. **The bond changes the game by not verifying a proof at all.** At **4.3 ns** it is
   ~500× faster than Merkle and ~4000× faster than a signature check, because "verify"
   is a state lookup a light client already has — **zero network round-trips, zero
   proof bytes**. The cost is a different trust model (economic + a watchtower), and
   failure is detected *after the fact*, not instantly.

4. **KZG / SNARK buy proof *size*, not verify *speed*.** Their proofs are the smallest
   (constant ~48 B), but verify is milliseconds. They win only when **bandwidth**, not
   CPU, is the bottleneck (e.g. broadcasting proofs to many light clients).

## Recommendation (hybrid, policy-selected)

No single scheme dominates — the right choice is **risk-dependent**, which maps cleanly
onto a `shouldEscalate`-style policy:

- **Low value / low uncertainty →** trust the **bond** (4 ns, 0 network). The common case.
- **High value / escalated →** demand a **fresh cryptographic proof**: `merkle-ct` for a
  self-hosted root, or a `kzg`/`snark` proof when proof size on the wire matters.

That is: the aggregate's freshness is one more **declared-and-echoed policy axis**
(`maxAttestationAge`), and the choice between "trust the bond" and "demand a proof" is
the same escalation switch used for statistical sufficiency.

## Caveats

- Verify-path only. Issuer-side `setup`/`prove` (root construction, witness generation)
  is amortized once per window and not the focus here.
- `rsa-accumulator` uses a demo modulus (factorization hardness irrelevant to timing);
  the accumulator arithmetic is real.
- `kzg-verkle` and `recursive-snark` rows are **literature order-of-magnitude proxies**,
  not measured here — implementing them for real (blst/arkworks, Halo2/Nova) is a
  separate track.

## Related: the precedence half

This bench measures **freshness** — "is this agent verifiably alive/current *now*?"
The complementary problem is **precedence** — "did this claim exist *no later than* T?"
(monotone once anchored, never decays). A live third-party reference implementation:

- [`api.babyblueviper.com/ledger`](https://api.babyblueviper.com/ledger) — an
  OTS-anchored public verdict ledger ([invinoveritas](https://github.com/babyblueviper1/invinoveritas)).
  Two tiers: Nostr relay attestation (fast) and OpenTimestamps Bitcoin anchoring (firm).
  **Independently verified here (2026-07-16):** the relay tier checks out — events fetched
  from public relays, NIP-01 id recomputed, BIP-340 signature valid against the published
  pubkey (3/3 sampled entries). The OTS tier is not yet third-party-runnable: the `.ots`
  proof files referenced by each entry are not publicly served (see
  [issue #1](https://github.com/hanjoonchoe/liveness-bench/issues/1)).
  Third-party service, independently operated.

Note per the ethereum-magicians discussion (posts 289–294): the `crypto-economic-bond`
row above is a correctness/status read, not a liveness *proof* — liveness itself is
confirmed by the request, with attestation as a selection-time prefilter.
