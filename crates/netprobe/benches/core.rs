//! Microbenchmarks for hot, allocation-sensitive helpers.

use criterion::{Criterion, criterion_group, criterion_main};
use netprobe::probe::{http, icmp};
use netprobe::stats::summarize;
use netprobe::target::parse_endpoint;
use netprobe::url::parse_url;
use std::hint::black_box;

fn bench(c: &mut Criterion) {
    c.bench_function("parse_endpoint/hostname", |b| {
        b.iter(|| parse_endpoint(black_box("service.internal.example.com:8443"), None))
    });
    c.bench_function("parse_endpoint/ipv6", |b| {
        b.iter(|| parse_endpoint(black_box("[2001:db8::1]:443"), None))
    });
    c.bench_function("parse_url", |b| {
        b.iter(|| parse_url(black_box("https://api.example.com:8443/v1/health?probe=1")))
    });
    c.bench_function("http/parse_status_line", |b| {
        b.iter(|| http::parse_status_line(black_box(b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n")))
    });
    c.bench_function("icmp/build_echo", |b| {
        b.iter(|| icmp::build_echo(false, black_box(0x1234), black_box(7)))
    });
    let samples: Vec<f64> = (0..10_000)
        .map(|i| f64::from((i * 7919) % 10_007) / 10.0)
        .collect();
    c.bench_function("stats/summarize_10k", |b| {
        b.iter_batched(
            || samples.clone(),
            |mut v| summarize(black_box(&mut v)),
            criterion::BatchSize::LargeInput,
        )
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
