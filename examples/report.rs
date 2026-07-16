//! Prints the proof-size / root-size / verify-shape table (the part criterion
//! doesn't measure). Run: `cargo run --release --example report`.

use liveness_bench::*;

fn main() {
    let n = 1000usize;
    let target = n / 2;

    println!("liveness/freshness schemes — N = {n} agents, proving agent {target}\n");
    println!(
        "{:<22} | {:>12} | {:>16} | verify",
        "scheme", "proof bytes", "root/window B"
    );
    println!("{}", "-".repeat(78));

    macro_rules! row {
        ($ty:ty, $note:expr) => {{
            let s = <$ty>::setup(n);
            let p = s.prove(target);
            println!(
                "{:<22} | {:>12} | {:>16} | {}",
                s.name(),
                p.len(),
                s.root_bytes(),
                $note
            );
        }};
    }

    row!(Naive, "1 Ed25519 verify; NO shared root (fetch N)");
    row!(Merkle, "~log2(N) SHA-256 hashes");
    row!(SigAttestation, "1 Ed25519 verify (cached over window)");
    row!(RsaAccumulator, "1 modexp — O(1) in N (big constant)");
    row!(Bond, "O(1) state lookup; 0 network round-trips");

    println!("\n--- literature proxies (not benchmarked here) ---");
    for px in PROXIES {
        println!(
            "{:<22} | {:>12} | {:>16} | {}",
            px.name, px.proof_bytes, px.root_bytes, px.verify_note
        );
    }
}
