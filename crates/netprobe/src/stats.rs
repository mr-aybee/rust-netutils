//! Latency summary statistics.

use serde::Serialize;

/// Summary of a series of latency samples in milliseconds.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Summary {
    /// Lowest sample.
    pub min_ms: f64,
    /// Mean of the samples.
    pub avg_ms: f64,
    /// Median (nearest rank).
    pub p50_ms: f64,
    /// 95th percentile (nearest rank).
    pub p95_ms: f64,
    /// Highest sample.
    pub max_ms: f64,
    /// Population standard deviation.
    pub stddev_ms: f64,
}

/// Nearest-rank percentile over a sorted slice. `q` in (0, 100].
fn percentile(sorted: &[f64], q: f64) -> f64 {
    let rank = ((q / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// Compute a summary; returns `None` for an empty input.
/// Sorts `samples` in place to avoid an extra allocation.
pub fn summarize(samples: &mut [f64]) -> Option<Summary> {
    if samples.is_empty() {
        return None;
    }

    samples.sort_by(f64::total_cmp);
    let n = samples.len() as f64;
    let avg = samples.iter().sum::<f64>() / n;
    let var = samples.iter().map(|x| (x - avg).powi(2)).sum::<f64>() / n;
    Some(Summary {
        min_ms: samples[0],
        avg_ms: avg,
        p50_ms: percentile(samples, 50.0),
        p95_ms: percentile(samples, 95.0),
        max_ms: samples[samples.len() - 1],
        stddev_ms: var.sqrt(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        assert_eq!(summarize(&mut []), None);
    }

    #[test]
    fn known_values() {
        let mut v: Vec<f64> = (1..=100).map(f64::from).rev().collect();
        let s = summarize(&mut v).unwrap();
        assert_eq!(s.min_ms, 1.0);
        assert_eq!(s.max_ms, 100.0);
        assert_eq!(s.p50_ms, 50.0);
        assert_eq!(s.p95_ms, 95.0);
        assert!((s.avg_ms - 50.5).abs() < 1e-9);
    }

    #[test]
    fn single() {
        let s = summarize(&mut [7.0]).unwrap();
        assert_eq!(
            (s.min_ms, s.p50_ms, s.p95_ms, s.max_ms, s.stddev_ms),
            (7.0, 7.0, 7.0, 7.0, 0.0)
        );
    }

    proptest::proptest! {
        #[test]
        fn ordered(mut v in proptest::collection::vec(0.0f64..1e6, 1..200)) {
            let s = summarize(&mut v).unwrap();
            proptest::prop_assert!(s.min_ms <= s.p50_ms && s.p50_ms <= s.p95_ms && s.p95_ms <= s.max_ms);
            proptest::prop_assert!(s.min_ms <= s.avg_ms + 1e-6 && s.avg_ms <= s.max_ms + 1e-6);
        }
    }
}
