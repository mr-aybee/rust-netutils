//! Rolling per-host statistics over a bounded window of samples.

use serde::Serialize;
use std::collections::VecDeque;

/// Statistics for one host: lifetime counters plus a rolling window.
#[derive(Debug, Clone)]
pub struct HostStats {
    window: VecDeque<Option<f64>>,
    capacity: usize,
    pub sent: u64,
    pub received: u64,
    pub last_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Snapshot {
    pub sent: u64,
    pub received: u64,
    /// Loss over the whole run, percent.
    pub loss_pct: f64,
    /// Loss within the rolling window, percent.
    pub window_loss_pct: f64,
    pub last_ms: Option<f64>,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub max_ms: Option<f64>,
    /// Mean absolute difference between consecutive successful samples (RFC 3550-style jitter, unsmoothed).
    pub jitter_ms: Option<f64>,
}

impl HostStats {
    pub fn new(window: usize) -> Self {
        let capacity = window.max(1);
        Self {
            window: VecDeque::with_capacity(capacity),
            capacity,
            sent: 0,
            received: 0,
            last_ms: None,
        }
    }

    /// Record one probe: `Some(rtt_ms)` for a reply, `None` for loss.
    pub fn record(&mut self, rtt_ms: Option<f64>) {
        self.sent += 1;
        if let Some(r) = rtt_ms {
            self.received += 1;
            self.last_ms = Some(r);
        }
        if self.window.len() == self.capacity {
            self.window.pop_front();
        }
        self.window.push_back(rtt_ms);
    }

    pub fn snapshot(&self) -> Snapshot {
        let ok: Vec<f64> = self.window.iter().flatten().copied().collect();
        let mut sorted = ok.clone();
        sorted.sort_by(f64::total_cmp);
        let p95 = (!sorted.is_empty()).then(|| {
            let rank = ((0.95 * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
            sorted[rank - 1]
        });
        let jitter = (ok.len() >= 2).then(|| {
            ok.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (ok.len() - 1) as f64
        });
        let pct = |lost: u64, total: u64| {
            if total == 0 {
                0.0
            } else {
                lost as f64 * 100.0 / total as f64
            }
        };
        let wlen = self.window.len() as u64;
        Snapshot {
            sent: self.sent,
            received: self.received,
            loss_pct: pct(self.sent - self.received, self.sent),
            window_loss_pct: pct(wlen - ok.len() as u64, wlen),
            last_ms: self.last_ms,
            min_ms: sorted.first().copied(),
            avg_ms: (!ok.is_empty()).then(|| ok.iter().sum::<f64>() / ok.len() as f64),
            p95_ms: p95,
            max_ms: sorted.last().copied(),
            jitter_ms: jitter,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_is_bounded_and_loss_counted() {
        let mut s = HostStats::new(3);
        for r in [Some(1.0), None, Some(3.0), Some(5.0)] {
            s.record(r);
        }
        let snap = s.snapshot();
        assert_eq!((snap.sent, snap.received), (4, 3));
        assert_eq!(snap.loss_pct, 25.0);
        // Window holds [None, 3, 5].
        assert!((snap.window_loss_pct - 100.0 / 3.0).abs() < 1e-9);
        assert_eq!(
            (snap.min_ms, snap.max_ms, snap.avg_ms),
            (Some(3.0), Some(5.0), Some(4.0))
        );
        assert_eq!(snap.jitter_ms, Some(2.0));
        assert_eq!(snap.last_ms, Some(5.0));
    }

    #[test]
    fn empty_and_all_lost() {
        assert_eq!(HostStats::new(5).snapshot().loss_pct, 0.0);
        let mut s = HostStats::new(5);
        s.record(None);
        let snap = s.snapshot();
        assert_eq!(
            (snap.loss_pct, snap.avg_ms, snap.jitter_ms),
            (100.0, None, None)
        );
    }

    proptest::proptest! {
        #[test]
        fn invariants(samples in proptest::collection::vec(proptest::option::of(0.0f64..10_000.0), 1..300), w in 1usize..100) {
            let mut s = HostStats::new(w);
            for x in &samples { s.record(*x); }
            let snap = s.snapshot();
            proptest::prop_assert_eq!(snap.sent, samples.len() as u64);
            proptest::prop_assert!(snap.loss_pct >= 0.0 && snap.loss_pct <= 100.0);
            if let (Some(min), Some(p95), Some(max)) = (snap.min_ms, snap.p95_ms, snap.max_ms) {
                proptest::prop_assert!(min <= p95 && p95 <= max);
            }
        }
    }
}
