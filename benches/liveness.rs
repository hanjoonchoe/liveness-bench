use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use liveness_bench::*;

/// Per-gating verify cost of every scheme at a fixed N (the hot path a consumer
/// pays on every gating decision).
fn verify_per_gating(c: &mut Criterion) {
    let n = 1000usize;
    let target = n / 2;
    let mut group = c.benchmark_group("verify_per_gating_n1000");

    macro_rules! bench_scheme {
        ($ty:ty) => {{
            let s = <$ty>::setup(n);
            let proof = s.prove(target);
            group.bench_function(s.name(), |b| {
                b.iter(|| s.verify(black_box(target), black_box(&proof)))
            });
        }};
    }

    bench_scheme!(Naive);
    bench_scheme!(Merkle);
    bench_scheme!(SigAttestation);
    bench_scheme!(RsaAccumulator);
    bench_scheme!(Bond);
    group.finish();
}

/// How Merkle verify scales with N (should be ~log N), vs. the O(1) schemes which
/// stay flat.
fn scaling_with_n(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_scaling");
    for &n in &[100usize, 1_000, 10_000, 100_000] {
        let target = n / 2;

        let m = Merkle::setup(n);
        let mp = m.prove(target);
        group.bench_with_input(BenchmarkId::new("merkle", n), &n, |b, _| {
            b.iter(|| m.verify(black_box(target), black_box(&mp)))
        });

        let s = SigAttestation::setup(n);
        let sp = s.prove(target);
        group.bench_with_input(BenchmarkId::new("sig-attestation", n), &n, |b, _| {
            b.iter(|| s.verify(black_box(target), black_box(&sp)))
        });

        let bond = Bond::setup(n);
        group.bench_with_input(BenchmarkId::new("bond", n), &n, |b, _| {
            b.iter(|| bond.verify(black_box(target), black_box(&[])))
        });
    }
    group.finish();
}

criterion_group!(benches, verify_per_gating, scaling_with_n);
criterion_main!(benches);
