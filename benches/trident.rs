#![allow(missing_docs)]

use core::hint::black_box;
use criterion::{Criterion, criterion_group, criterion_main};

fn bench(c: &mut Criterion) {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);

    c.bench_function("trident/keygen", |b| {
        b.iter(|| trident::DecapsulationKey::generate_from_rng(&mut rng));
    });

    let (dk, ek) = trident::generate_key_pair_from_rng(&mut rng);
    c.bench_function("trident/encapsulate", |b| {
        b.iter(|| black_box(&ek).encapsulate_with_rng(&mut rng));
    });

    let (ct, _) = ek.encapsulate_with_rng(&mut rng);
    c.bench_function("trident/decapsulate", |b| {
        b.iter(|| black_box(&dk).decapsulate(black_box(&ct)));
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
