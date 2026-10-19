//! Runtime readiness, replay and per-actor resource controls.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type ActorId = [u8; 16];
pub type MessageId = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Ready,
    Degraded,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessCheck {
    pub code: String,
    pub status: CheckStatus,
    pub observed_unix_ms: u64,
    pub measurement: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverallStatus {
    Ready,
    Degraded,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessSnapshot {
    pub source_version: String,
    pub generated_unix_ms: u64,
    pub overall: OverallStatus,
    pub checks: Vec<ReadinessCheck>,
}

#[derive(Debug)]
pub struct ReadinessRegistry {
    source_version: String,
    required: BTreeSet<String>,
    checks: BTreeMap<String, ReadinessCheck>,
}

impl ReadinessRegistry {
    pub fn new(
        source_version: String,
        required: impl IntoIterator<Item = String>,
    ) -> Result<Self, OperationsError> {
        if source_version.is_empty() {
            return Err(OperationsError::Invalid);
        }
        let required = required.into_iter().collect::<BTreeSet<_>>();
        if required.is_empty() || required.iter().any(String::is_empty) {
            return Err(OperationsError::Invalid);
        }
        Ok(Self {
            source_version,
            required,
            checks: BTreeMap::new(),
        })
    }

    pub fn update(&mut self, check: ReadinessCheck) -> Result<(), OperationsError> {
        if check.code.is_empty() || check.code.len() > 128 {
            return Err(OperationsError::Invalid);
        }
        self.checks.insert(check.code.clone(), check);
        Ok(())
    }

    #[must_use]
    pub fn snapshot(&self, generated_unix_ms: u64) -> ReadinessSnapshot {
        let mut checks = self.checks.values().cloned().collect::<Vec<_>>();
        for missing in self
            .required
            .difference(&self.checks.keys().cloned().collect())
        {
            checks.push(ReadinessCheck {
                code: missing.clone(),
                status: CheckStatus::Blocked,
                observed_unix_ms: generated_unix_ms,
                measurement: None,
            });
        }
        checks.sort_by(|left, right| left.code.cmp(&right.code));
        let overall = if checks
            .iter()
            .any(|check| check.status == CheckStatus::Blocked)
        {
            OverallStatus::Blocked
        } else if checks
            .iter()
            .any(|check| check.status == CheckStatus::Degraded)
        {
            OverallStatus::Degraded
        } else {
            OverallStatus::Ready
        };
        ReadinessSnapshot {
            source_version: self.source_version.clone(),
            generated_unix_ms,
            overall,
            checks,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActorLimits {
    pub calls_per_window: u64,
    pub bytes_per_window: u64,
    pub callbacks_per_window: u64,
    pub diagnostics_per_window: u64,
    pub window_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceCharge {
    pub calls: u64,
    pub bytes: u64,
    pub callbacks: u64,
    pub diagnostics: u64,
}

#[derive(Debug, Clone, Copy)]
struct Usage {
    window_start_ms: u64,
    charge: ResourceCharge,
}

#[derive(Debug)]
pub struct ActorLimiter {
    limits: ActorLimits,
    actors: BTreeMap<ActorId, Usage>,
}

impl ActorLimiter {
    pub fn new(limits: ActorLimits) -> Result<Self, OperationsError> {
        if limits.calls_per_window == 0
            || limits.bytes_per_window == 0
            || limits.callbacks_per_window == 0
            || limits.diagnostics_per_window == 0
            || limits.window_ms == 0
        {
            return Err(OperationsError::Invalid);
        }
        Ok(Self {
            limits,
            actors: BTreeMap::new(),
        })
    }

    pub fn charge(
        &mut self,
        actor: ActorId,
        now_unix_ms: u64,
        charge: ResourceCharge,
    ) -> Result<(), OperationsError> {
        let usage = self.actors.entry(actor).or_insert(Usage {
            window_start_ms: now_unix_ms,
            charge: zero_charge(),
        });
        if now_unix_ms.saturating_sub(usage.window_start_ms) >= self.limits.window_ms {
            usage.window_start_ms = now_unix_ms;
            usage.charge = zero_charge();
        }
        let next = add_charge(usage.charge, charge)?;
        if next.calls > self.limits.calls_per_window
            || next.bytes > self.limits.bytes_per_window
            || next.callbacks > self.limits.callbacks_per_window
            || next.diagnostics > self.limits.diagnostics_per_window
        {
            return Err(OperationsError::RateLimited);
        }
        usage.charge = next;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ReplayWindow {
    maximum: usize,
    seen: BTreeSet<MessageId>,
    order: VecDeque<MessageId>,
}

impl ReplayWindow {
    pub fn new(maximum: usize) -> Result<Self, OperationsError> {
        if maximum == 0 {
            return Err(OperationsError::Invalid);
        }
        Ok(Self {
            maximum,
            seen: BTreeSet::new(),
            order: VecDeque::new(),
        })
    }

    pub fn admit(&mut self, message_id: MessageId) -> Result<(), OperationsError> {
        if !self.seen.insert(message_id) {
            return Err(OperationsError::Replay);
        }
        self.order.push_back(message_id);
        if self.order.len() > self.maximum {
            let oldest = self.order.pop_front().ok_or(OperationsError::Invalid)?;
            self.seen.remove(&oldest);
        }
        Ok(())
    }

    pub fn restart(&mut self) {
        self.seen.clear();
        self.order.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationsError {
    Invalid,
    Overflow,
    RateLimited,
    Replay,
}

impl std::fmt::Display for OperationsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for OperationsError {}

const fn zero_charge() -> ResourceCharge {
    ResourceCharge {
        calls: 0,
        bytes: 0,
        callbacks: 0,
        diagnostics: 0,
    }
}

fn add_charge(
    current: ResourceCharge,
    added: ResourceCharge,
) -> Result<ResourceCharge, OperationsError> {
    Ok(ResourceCharge {
        calls: current
            .calls
            .checked_add(added.calls)
            .ok_or(OperationsError::Overflow)?,
        bytes: current
            .bytes
            .checked_add(added.bytes)
            .ok_or(OperationsError::Overflow)?,
        callbacks: current
            .callbacks
            .checked_add(added.callbacks)
            .ok_or(OperationsError::Overflow)?,
        diagnostics: current
            .diagnostics
            .checked_add(added.diagnostics)
            .ok_or(OperationsError::Overflow)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_is_truthful_and_missing_checks_block() {
        let mut readiness = ReadinessRegistry::new(
            String::from("0.2.0"),
            [String::from("state"), String::from("transport")],
        )
        .unwrap();
        readiness
            .update(ReadinessCheck {
                code: String::from("state"),
                status: CheckStatus::Ready,
                observed_unix_ms: 1,
                measurement: Some(3),
            })
            .unwrap();
        let snapshot = readiness.snapshot(2);
        assert_eq!(snapshot.overall, OverallStatus::Blocked);
        readiness
            .update(ReadinessCheck {
                code: String::from("transport"),
                status: CheckStatus::Degraded,
                observed_unix_ms: 3,
                measurement: None,
            })
            .unwrap();
        assert_eq!(readiness.snapshot(4).overall, OverallStatus::Degraded);
    }

    #[test]
    fn actor_limits_are_scoped_reset_and_fail_before_commit() {
        let mut limiter = ActorLimiter::new(ActorLimits {
            calls_per_window: 2,
            bytes_per_window: 10,
            callbacks_per_window: 1,
            diagnostics_per_window: 1,
            window_ms: 100,
        })
        .unwrap();
        let charge = ResourceCharge {
            calls: 1,
            bytes: 5,
            callbacks: 0,
            diagnostics: 0,
        };
        limiter.charge([1; 16], 0, charge).unwrap();
        limiter.charge([1; 16], 1, charge).unwrap();
        assert_eq!(
            limiter.charge([1; 16], 2, charge),
            Err(OperationsError::RateLimited)
        );
        limiter.charge([2; 16], 2, charge).unwrap();
        limiter.charge([1; 16], 100, charge).unwrap();
    }

    #[test]
    fn replay_window_is_bounded_and_restart_scoped() {
        let mut replay = ReplayWindow::new(2).unwrap();
        replay.admit([1; 16]).unwrap();
        assert_eq!(replay.admit([1; 16]), Err(OperationsError::Replay));
        replay.admit([2; 16]).unwrap();
        replay.admit([3; 16]).unwrap();
        replay.admit([1; 16]).unwrap();
        replay.restart();
        replay.admit([1; 16]).unwrap();
    }
}
