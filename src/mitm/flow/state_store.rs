use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

#[derive(Clone, Debug)]
pub struct FilterStateLimits {
    pub ttl: Duration,
    pub max_entry_bytes: usize,
    pub max_connection_bytes: usize,
    pub max_filter_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for FilterStateLimits {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(60),
            max_entry_bytes: 256 * 1024,
            max_connection_bytes: 2 * 1024 * 1024,
            max_filter_bytes: 16 * 1024 * 1024,
            max_total_bytes: 128 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StateOpStats {
    pub read_bytes: i64,
    pub write_bytes: i64,
    pub state_items: i64,
    pub evicted_items: i64,
    pub limit_hit: bool,
}

#[derive(Clone, Debug)]
pub enum StatePutOutcome {
    Stored,
    Replaced,
    RejectedEntryTooLarge,
    RejectedConnectionLimit,
    RejectedFilterLimit,
    RejectedTotalLimit,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct StateKey {
    connection_id: String,
    filter_name: String,
    user_key: String,
}

#[derive(Clone, Debug)]
struct StateEntry {
    value: Vec<u8>,
    created_at: Instant,
    last_access_at: Instant,
}

#[derive(Debug, Default)]
struct StateIndex {
    entries: HashMap<StateKey, StateEntry>,
    connection_bytes: HashMap<String, usize>,
    filter_bytes: HashMap<String, usize>,
    total_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct FilterStateStore {
    limits: FilterStateLimits,
    inner: Arc<Mutex<StateIndex>>,
}

impl FilterStateStore {
    pub fn new(limits: FilterStateLimits) -> Self {
        Self {
            limits,
            inner: Arc::new(Mutex::new(StateIndex::default())),
        }
    }

    pub fn get(&self, connection_id: &str, filter_name: &str, user_key: &str) -> (Option<Vec<u8>>, StateOpStats) {
        let mut stats = StateOpStats::default();
        let now = Instant::now();
        let key = StateKey {
            connection_id: connection_id.to_string(),
            filter_name: filter_name.to_string(),
            user_key: user_key.to_string(),
        };

        let mut inner = self.inner.lock();

        if let Some(entry) = inner.entries.get(&key) {
            if now.duration_since(entry.last_access_at) > self.limits.ttl {
                drop_entry(&mut inner, &key);
                stats.evicted_items += 1;
                stats.state_items = inner.entries.len() as i64;
                return (None, stats);
            }
        } else {
            stats.state_items = inner.entries.len() as i64;
            return (None, stats);
        }

        let value = {
            let entry = inner.entries.get_mut(&key).expect("checked above");
            entry.last_access_at = now;
            entry.value.clone()
        };

        stats.read_bytes = value.len() as i64;
        stats.state_items = inner.entries.len() as i64;
        (Some(value), stats)
    }

    pub fn put(&self, connection_id: &str, filter_name: &str, user_key: &str, value: Vec<u8>) -> (StatePutOutcome, StateOpStats) {
        let mut stats = StateOpStats::default();

        if value.len() > self.limits.max_entry_bytes {
            stats.limit_hit = true;
            return (StatePutOutcome::RejectedEntryTooLarge, stats);
        }

        let now = Instant::now();
        let key = StateKey {
            connection_id: connection_id.to_string(),
            filter_name: filter_name.to_string(),
            user_key: user_key.to_string(),
        };

        let mut inner = self.inner.lock();
        sweep_expired_locked(&mut inner, self.limits.ttl, now, &mut stats);

        let old_len = inner.entries.get(&key).map(|entry| entry.value.len()).unwrap_or(0);
        let delta = value.len().saturating_sub(old_len);

        let conn_used = *inner.connection_bytes.get(connection_id).unwrap_or(&0);
        let filter_used = *inner.filter_bytes.get(filter_name).unwrap_or(&0);

        if conn_used + delta > self.limits.max_connection_bytes {
            stats.limit_hit = true;
            stats.state_items = inner.entries.len() as i64;
            return (StatePutOutcome::RejectedConnectionLimit, stats);
        }

        if filter_used + delta > self.limits.max_filter_bytes {
            stats.limit_hit = true;
            stats.state_items = inner.entries.len() as i64;
            return (StatePutOutcome::RejectedFilterLimit, stats);
        }

        if inner.total_bytes + delta > self.limits.max_total_bytes {
            stats.limit_hit = true;
            stats.state_items = inner.entries.len() as i64;
            return (StatePutOutcome::RejectedTotalLimit, stats);
        }

        inner.total_bytes += delta;
        inner.connection_bytes.insert(connection_id.to_string(), conn_used + delta);
        inner.filter_bytes.insert(filter_name.to_string(), filter_used + delta);

        let outcome = if inner.entries.contains_key(&key) {
            StatePutOutcome::Replaced
        } else {
            StatePutOutcome::Stored
        };

        inner.entries.insert(
            key,
            StateEntry {
                value,
                created_at: now,
                last_access_at: now,
            },
        );

        stats.write_bytes = delta as i64;
        stats.state_items = inner.entries.len() as i64;
        (outcome, stats)
    }

    pub fn delete(&self, connection_id: &str, filter_name: &str, user_key: &str) -> StateOpStats {
        let mut stats = StateOpStats::default();
        let key = StateKey {
            connection_id: connection_id.to_string(),
            filter_name: filter_name.to_string(),
            user_key: user_key.to_string(),
        };

        let mut inner = self.inner.lock();
        if drop_entry(&mut inner, &key) {
            stats.evicted_items = 1;
        }
        stats.state_items = inner.entries.len() as i64;
        stats
    }

    pub fn sweep_expired(&self) -> StateOpStats {
        let mut stats = StateOpStats::default();
        let now = Instant::now();
        let mut inner = self.inner.lock();
        sweep_expired_locked(&mut inner, self.limits.ttl, now, &mut stats);
        stats.state_items = inner.entries.len() as i64;
        stats
    }
}

fn sweep_expired_locked(inner: &mut StateIndex, ttl: Duration, now: Instant, stats: &mut StateOpStats) {
    let expired = inner
        .entries
        .iter()
        .filter_map(|(key, entry)| {
            let idle_expired = now.duration_since(entry.last_access_at) > ttl;
            let born_expired = now.duration_since(entry.created_at) > ttl;
            (idle_expired || born_expired).then_some(key.clone())
        })
        .collect::<Vec<_>>();

    for key in expired {
        if drop_entry(inner, &key) {
            stats.evicted_items += 1;
        }
    }
}

fn drop_entry(inner: &mut StateIndex, key: &StateKey) -> bool {
    let Some(entry) = inner.entries.remove(key) else {
        return false;
    };

    let len = entry.value.len();
    inner.total_bytes = inner.total_bytes.saturating_sub(len);

    if let Some(used) = inner.connection_bytes.get_mut(&key.connection_id) {
        *used = used.saturating_sub(len);
        if *used == 0 {
            inner.connection_bytes.remove(&key.connection_id);
        }
    }

    if let Some(used) = inner.filter_bytes.get_mut(&key.filter_name) {
        *used = used.saturating_sub(len);
        if *used == 0 {
            inner.filter_bytes.remove(&key.filter_name);
        }
    }

    true
}