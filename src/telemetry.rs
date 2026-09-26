//! Process-local counters for proxy lifecycle and request outcomes.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    active_sessions: AtomicU64,
    accepted_connections: AtomicU64,
    active_connections: AtomicU64,
    denied_requests: AtomicU64,
    upstream_failures: AtomicU64,
    interception_errors: AtomicU64,
    forced_shutdowns: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub active_sessions: u64,
    pub accepted_connections: u64,
    pub active_connections: u64,
    pub denied_requests: u64,
    pub upstream_failures: u64,
    pub interception_errors: u64,
    pub forced_shutdowns: u64,
}

impl Metrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            denied_requests: self.denied_requests.load(Ordering::Relaxed),
            upstream_failures: self.upstream_failures.load(Ordering::Relaxed),
            interception_errors: self.interception_errors.load(Ordering::Relaxed),
            forced_shutdowns: self.forced_shutdowns.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn session_started(&self) -> u64 {
        self.active_sessions.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(crate) fn session_stopped(&self) -> u64 {
        self.active_sessions.fetch_sub(1, Ordering::Relaxed) - 1
    }

    pub(crate) fn connection_started(&self) {
        self.accepted_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn connection_stopped(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn denied_request(&self) -> u64 {
        self.denied_requests.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(crate) fn upstream_failure(&self) -> u64 {
        self.upstream_failures.fetch_add(1, Ordering::Relaxed) + 1
    }

    // The current fail-closed handler does not attempt TLS interception. Keep
    // the counter ready for the interception hook added with policy enforcement.
    #[allow(dead_code)]
    pub(crate) fn interception_error(&self) -> u64 {
        self.interception_errors.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(crate) fn forced_shutdown(&self) -> u64 {
        self.forced_shutdowns.fetch_add(1, Ordering::Relaxed) + 1
    }
}

#[cfg(test)]
mod tests {
    use super::Metrics;

    #[test]
    fn snapshots_report_counters_and_active_gauges() {
        let metrics = Metrics::default();
        metrics.session_started();
        metrics.connection_started();
        metrics.denied_request();
        metrics.upstream_failure();
        metrics.interception_error();
        metrics.forced_shutdown();

        assert_eq!(
            metrics.snapshot(),
            super::MetricsSnapshot {
                active_sessions: 1,
                accepted_connections: 1,
                active_connections: 1,
                denied_requests: 1,
                upstream_failures: 1,
                interception_errors: 1,
                forced_shutdowns: 1,
            }
        );

        metrics.connection_stopped();
        metrics.session_stopped();
        assert_eq!(metrics.snapshot().active_connections, 0);
        assert_eq!(metrics.snapshot().active_sessions, 0);
    }
}
