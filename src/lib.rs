//! Benchmark harness for agent liveness/freshness verification schemes.
//!
//! Every scheme answers the same question — "prove agent `i` was fresh as of the last
//! committed state, and let a consumer verify it" — but with very different per-gating
//! cost, proof size, and what the consumer must fetch per window. We measure the
//! *consumer's per-gating verify path*, which is the cost that multiplies by the number
//! of gating decisions.
//!
//! Implemented and measured for real: [`Naive`], [`Merkle`], [`SigAttestation`],
//! [`RsaAccumulator`], [`Bond`]. KZG/Verkle and recursive-SNARK are documented as
//! literature proxies in `PROXIES` (implementing them for real is a separate track).

use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use sha2::{Digest, Sha256};

/// A freshness scheme. `setup` is the issuer-side one-time cost; `verify` is the
/// consumer-side per-gating cost that the benchmark focuses on.
pub trait LivenessScheme {
    fn name(&self) -> &'static str;
    /// Build state for `n` agents (issuer side, amortized once per window).
    fn setup(n: usize) -> Self
    where
        Self: Sized;
    /// The freshness proof a consumer needs for agent `i`.
    fn prove(&self, agent: usize) -> Vec<u8>;
    /// Consumer-side verification — the per-gating hot path.
    fn verify(&self, agent: usize, proof: &[u8]) -> bool;
    /// Bytes the consumer must fetch per window to stay fresh (the aggregate root).
    fn root_bytes(&self) -> usize;
}

// ---------------------------------------------------------------------------
// 1. Naive per-call: each agent self-signs its liveness; no aggregate. The
//    consumer must fetch and verify one signature *per agent* (no shared root),
//    and in the real world re-probe every gating decision. Verify = 1 Ed25519.
// ---------------------------------------------------------------------------

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub struct Naive {
    keys: Vec<VerifyingKey>,
    sigs: Vec<Signature>,
    msg: Vec<u8>,
}

impl LivenessScheme for Naive {
    fn name(&self) -> &'static str {
        "naive-per-call"
    }
    fn setup(n: usize) -> Self {
        let mut csprng = rand::rngs::OsRng;
        let msg = b"alive@block".to_vec();
        let mut keys = Vec::with_capacity(n);
        let mut sigs = Vec::with_capacity(n);
        for _ in 0..n {
            let sk = SigningKey::generate(&mut csprng);
            sigs.push(sk.sign(&msg));
            keys.push(sk.verifying_key());
        }
        Naive { keys, sigs, msg }
    }
    fn prove(&self, agent: usize) -> Vec<u8> {
        self.sigs[agent].to_bytes().to_vec()
    }
    fn verify(&self, agent: usize, proof: &[u8]) -> bool {
        let sig = Signature::from_slice(proof).unwrap();
        self.keys[agent].verify(&self.msg, &sig).is_ok()
    }
    fn root_bytes(&self) -> usize {
        0 // no aggregate: consumer fetches N individual keys/sigs
    }
}

// ---------------------------------------------------------------------------
// 2. Merkle inclusion (Certificate-Transparency style): one signed root commits
//    all N agents. Proof = O(log N) sibling hashes; verify recomputes the root.
// ---------------------------------------------------------------------------

pub struct Merkle {
    layers: Vec<Vec<[u8; 32]>>, // layers[0] = leaves, last = [root]
    root: [u8; 32],
}

fn h(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
fn h2(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize().into()
}

impl LivenessScheme for Merkle {
    fn name(&self) -> &'static str {
        "merkle-ct"
    }
    fn setup(n: usize) -> Self {
        let mut leaves: Vec<[u8; 32]> = (0..n)
            .map(|i| h(format!("agent{i}:alive@block").as_bytes()))
            .collect();
        if leaves.is_empty() {
            leaves.push([0u8; 32]);
        }
        let mut layers = vec![leaves];
        while layers.last().unwrap().len() > 1 {
            let prev = layers.last().unwrap();
            let mut next = Vec::with_capacity((prev.len() + 1) / 2);
            for pair in prev.chunks(2) {
                let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
                next.push(h2(&pair[0], right));
            }
            layers.push(next);
        }
        let root = layers.last().unwrap()[0];
        Merkle { layers, root }
    }
    fn prove(&self, agent: usize) -> Vec<u8> {
        // copath: one sibling hash per level
        let mut proof = Vec::new();
        let mut idx = agent;
        for layer in &self.layers[..self.layers.len() - 1] {
            let sib = if idx % 2 == 0 {
                (idx + 1).min(layer.len() - 1)
            } else {
                idx - 1
            };
            proof.push(idx as u8 & 1); // direction bit
            proof.extend_from_slice(&layer[sib]);
            idx /= 2;
        }
        proof
    }
    fn verify(&self, agent: usize, proof: &[u8]) -> bool {
        let mut acc = h(format!("agent{agent}:alive@block").as_bytes());
        let mut cur = proof;
        let mut idx = agent;
        while cur.len() >= 33 {
            let dir = cur[0] & 1;
            let mut sib = [0u8; 32];
            sib.copy_from_slice(&cur[1..33]);
            acc = if dir == 0 { h2(&acc, &sib) } else { h2(&sib, &acc) };
            cur = &cur[33..];
            idx /= 2;
        }
        let _ = idx;
        acc == self.root
    }
    fn root_bytes(&self) -> usize {
        32 // consumer fetches one signed root per window
    }
}

// ---------------------------------------------------------------------------
// 3. Signature attestation + window: a single attestor signs each agent's
//    liveness once per window; the consumer caches the signature and only
//    verifies (no re-sign on the hot path). Verify = 1 Ed25519. Aggregate root
//    is the attestor's public key.
// ---------------------------------------------------------------------------

pub struct SigAttestation {
    attestor: VerifyingKey,
    sigs: Vec<Signature>,
    msgs: Vec<Vec<u8>>,
}

impl LivenessScheme for SigAttestation {
    fn name(&self) -> &'static str {
        "sig-attestation"
    }
    fn setup(n: usize) -> Self {
        let mut csprng = rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let mut sigs = Vec::with_capacity(n);
        let mut msgs = Vec::with_capacity(n);
        for i in 0..n {
            let m = format!("agent{i}:alive@block").into_bytes();
            sigs.push(sk.sign(&m));
            msgs.push(m);
        }
        SigAttestation {
            attestor: sk.verifying_key(),
            sigs,
            msgs,
        }
    }
    fn prove(&self, agent: usize) -> Vec<u8> {
        self.sigs[agent].to_bytes().to_vec()
    }
    fn verify(&self, agent: usize, proof: &[u8]) -> bool {
        let sig = Signature::from_slice(proof).unwrap();
        self.attestor.verify(&self.msgs[agent], &sig).is_ok()
    }
    fn root_bytes(&self) -> usize {
        32 // attestor public key
    }
}

// ---------------------------------------------------------------------------
// 4. RSA accumulator: a single constant-size accumulator commits all N agents.
//    Membership witness and verify are O(1) in N (but a big-integer modexp, so a
//    large constant). acc = g^(prod p_i) mod M; witness_x = g^(prod_{i!=x} p_i);
//    verify: witness_x^{p_x} == acc (mod M).
// ---------------------------------------------------------------------------

pub struct RsaAccumulator {
    modulus: BigUint,
    acc: BigUint,
    primes: Vec<u64>,
    witnesses: Vec<BigUint>,
}

fn first_n_odd_primes(n: usize) -> Vec<u64> {
    let mut primes = Vec::with_capacity(n);
    let mut cand = 3u64;
    while primes.len() < n {
        if (2..).take_while(|d| d * d <= cand).all(|d| cand % d != 0) {
            primes.push(cand);
        }
        cand += 2;
    }
    primes
}

impl LivenessScheme for RsaAccumulator {
    fn name(&self) -> &'static str {
        "rsa-accumulator"
    }
    fn setup(n: usize) -> Self {
        let mut rng = rand::thread_rng();
        // Demo modulus M = p*q of two large odds (factorization hardness irrelevant
        // for a micro-benchmark; the accumulator arithmetic holds regardless).
        let p = rng.gen_biguint(1024) | BigUint::one();
        let q = rng.gen_biguint(1024) | BigUint::one();
        let modulus = &p * &q;
        let g = BigUint::from(3u32);
        let primes = first_n_odd_primes(n.max(1));

        // full exponent P = prod p_i
        let mut full_exp = BigUint::one();
        for &pr in &primes {
            full_exp *= BigUint::from(pr);
        }
        let acc = g.modpow(&full_exp, &modulus);

        // witness_x = g^(P / p_x) mod M
        let witnesses = primes
            .iter()
            .map(|&pr| {
                let exp = &full_exp / BigUint::from(pr);
                g.modpow(&exp, &modulus)
            })
            .collect();

        RsaAccumulator {
            modulus,
            acc,
            primes,
            witnesses,
        }
    }
    fn prove(&self, agent: usize) -> Vec<u8> {
        self.witnesses[agent].to_bytes_be()
    }
    fn verify(&self, agent: usize, proof: &[u8]) -> bool {
        let witness = BigUint::from_bytes_be(proof);
        let px = BigUint::from(self.primes[agent]);
        witness.modpow(&px, &self.modulus) == self.acc
    }
    fn root_bytes(&self) -> usize {
        // the accumulator value (~2048-bit); consumer fetches one per window
        (self.acc.bits() as usize + 7) / 8
    }
}

// ---------------------------------------------------------------------------
// 5. Crypto-economic bond: no per-gating proof at all. Liveness is backed by a
//    stake that gets slashed on prolonged failure. The consumer just reads the
//    bond's on-chain status — which a light client already tracks under the state
//    root — so verify is an O(1) state lookup and network round-trips are zero.
// ---------------------------------------------------------------------------

use std::collections::HashMap;

pub struct Bond {
    slashed: HashMap<usize, bool>,
}

impl LivenessScheme for Bond {
    fn name(&self) -> &'static str {
        "crypto-economic-bond"
    }
    fn setup(n: usize) -> Self {
        let slashed = (0..n).map(|i| (i, false)).collect();
        Bond { slashed }
    }
    fn prove(&self, _agent: usize) -> Vec<u8> {
        Vec::new() // status is in shared state; nothing to ship
    }
    fn verify(&self, agent: usize, _proof: &[u8]) -> bool {
        // "bonded and not slashed" — an O(1) lookup, no network.
        matches!(self.slashed.get(&agent), Some(false))
    }
    fn root_bytes(&self) -> usize {
        32 // the state root a light client already follows; no extra fetch
    }
}

// ---------------------------------------------------------------------------
// Literature proxies — schemes we describe but do not implement here. Numbers
// are representative orders of magnitude from the cited work (see README).
// ---------------------------------------------------------------------------

pub struct Proxy {
    pub name: &'static str,
    pub verify_note: &'static str,
    pub proof_bytes: &'static str,
    pub root_bytes: &'static str,
}

pub const PROXIES: &[Proxy] = &[
    Proxy {
        name: "kzg-verkle",
        verify_note: "~1-2 ms (one pairing), O(1) in N",
        proof_bytes: "~48 B (constant)",
        root_bytes: "48 B",
    },
    Proxy {
        name: "recursive-snark",
        verify_note: "~2-10 ms, O(1) in N (N proofs folded into one)",
        proof_bytes: "~200 B - 1 KB (constant)",
        root_bytes: "~200 B",
    },
];
