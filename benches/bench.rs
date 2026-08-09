use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use deopti_transfer::fountain::{LtDecoder, LtEncoder};
use deopti_transfer::set::U32Set;
use deopti_transfer::simd::xor_into;
use deopti_transfer::soliton::{degree_binary, DegreeCdf};
use std::hint::black_box;

const BLOCK_LEN: usize = 2933;

fn payload(mb: usize) -> Vec<u8> {
    vec![0x5a; mb * 1024 * 1024]
}

fn bench_xor(c: &mut Criterion) {
    let n = 1 << 20;
    let mut dst = vec![0u32; n];
    let src = vec![0xdead_beefu32; n];
    let mut group = c.benchmark_group("xor");
    group.throughput(Throughput::Bytes((n * 4) as u64));
    group.bench_function("dispatched", |b| {
        b.iter(|| xor_into(&mut dst, &src));
    });
    group.bench_function("scalar_reference", |b| {
        b.iter(|| {
            for (d, s) in dst.iter_mut().zip(&src) {
                *d ^= *s;
            }
        });
    });
    group.finish();
}

fn bench_sample(c: &mut Criterion) {
    let mut group = c.benchmark_group("degree_sample");
    for &mb in &[1usize, 32] {
        let dc = DegreeCdf::new(payload(mb).len().div_ceil(BLOCK_LEN));
        let cdf = dc.cdf().to_vec();
        group.bench_with_input(BenchmarkId::new("quantized", mb), &dc, |b, dc| {
            b.iter(|| {
                let mut acc = 0usize;
                for i in 0..4096u32 {
                    acc += dc.sample((i as f64) / 4096.0);
                }
                black_box(acc);
            });
        });
        group.bench_with_input(BenchmarkId::new("binary", mb), &cdf, |b, cdf| {
            b.iter(|| {
                let mut acc = 0usize;
                for i in 0..4096u32 {
                    acc += degree_binary(cdf, (i as f64) / 4096.0);
                }
                black_box(acc);
            });
        });
    }
    group.finish();
}

fn bench_seen(c: &mut Criterion) {
    let mut group = c.benchmark_group("dedup");
    group.bench_function("u32_set_insert", |b| {
        let mut set = U32Set::with_capacity(1 << 16);
        b.iter(|| {
            for i in 0..1 << 16 {
                black_box(set.insert(i));
            }
        });
    });
    group.finish();
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");
    for &mb in &[1usize, 8, 32] {
        let data = payload(mb);
        let mut encoder = LtEncoder::new(&data, BLOCK_LEN, 42);
        let mut buf = vec![0u8; BLOCK_LEN];
        let frames = encoder.k() * 4 / 3 + 8;
        let out_bytes = frames * BLOCK_LEN;
        group.throughput(Throughput::Bytes(out_bytes as u64));
        group.bench_with_input(BenchmarkId::new("stream", mb), &frames, |b, &frames| {
            b.iter(|| {
                for seq in 0..frames as u32 {
                    encoder.encode_into(seq, &mut buf);
                }
                black_box(&buf);
            });
        });
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode");
    for &mb in &[1usize, 8, 32] {
        let data = payload(mb);
        let mut encoder = LtEncoder::new(&data, BLOCK_LEN, 42);
        let k = encoder.k();
        let mut frames = Vec::new();
        let mut verifier = LtDecoder::new(k, BLOCK_LEN, 42, data.len());
        for seq in 0..(k as u32).saturating_mul(8) {
            let frame = encoder.encode(seq);
            verifier.add_frame(seq, &frame);
            frames.push(frame);
            if verifier.is_complete() {
                break;
            }
        }
        assert!(
            verifier.is_complete(),
            "benchmark fixture must contain a complete decode"
        );
        let payload_len = data.len();
        group.throughput(Throughput::Bytes(payload_len as u64));
        group.bench_with_input(BenchmarkId::new("peel", mb), &frames, |b, frames| {
            b.iter(|| {
                let mut decoder = LtDecoder::new(k, BLOCK_LEN, 42, payload_len);
                for (seq, frame) in frames.iter().enumerate() {
                    decoder.add_frame(seq as u32, frame);
                    if decoder.is_complete() {
                        break;
                    }
                }
                black_box(decoder.assemble());
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_xor,
    bench_sample,
    bench_seen,
    bench_encode,
    bench_decode
);
criterion_main!(benches);
