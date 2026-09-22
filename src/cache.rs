//! Secrets approved per requesting instance.
//!
//! An entry is the approval itself: nothing is written to disk. It is dropped when its instance exits or after `IDLE_TTL_SECS` without being read by that instance.

use crate::process::Instance;
use crate::secret_ref::SecretRef;
use crate::vault::SecretValue;
use std::collections::HashMap;

pub const IDLE_TTL_SECS: u64 = 15 * 60;

struct Entry {
    value: SecretValue,
    last_used: u64,
}

#[derive(Default)]
pub struct Cache {
    instances: HashMap<Instance, HashMap<SecretRef, Entry>>,
}

impl Cache {
    /// The requested secrets this instance has no live entry for, in request order and without duplicates.
    pub fn missing(&self, instance: Instance, secrets: &[SecretRef], now: u64) -> Vec<SecretRef> {
        let cached = self.instances.get(&instance);
        let mut missing: Vec<SecretRef> = Vec::new();
        for secret in secrets {
            let live = cached
                .and_then(|entries| entries.get(secret))
                .is_some_and(|entry| !expired(entry, now));
            if !live && !missing.contains(secret) {
                missing.push(secret.clone());
            }
        }
        missing
    }

    pub fn insert(&mut self, instance: Instance, secret: SecretRef, value: SecretValue, now: u64) {
        self.instances.entry(instance).or_default().insert(
            secret,
            Entry {
                value,
                last_used: now,
            },
        );
    }

    /// Reads an entry and resets its idle timer. Expired entries read as absent.
    pub fn get(
        &mut self,
        instance: Instance,
        secret: &SecretRef,
        now: u64,
    ) -> Option<&SecretValue> {
        let entry = self.instances.get_mut(&instance)?.get_mut(secret)?;
        if expired(entry, now) {
            return None;
        }
        entry.last_used = now;
        Some(&entry.value)
    }

    /// Drops idle entries and every entry of an instance that is no longer alive. Dropping zeroes the value.
    pub fn sweep(&mut self, now: u64, is_alive: impl Fn(Instance) -> bool) {
        self.instances.retain(|&instance, entries| {
            if !is_alive(instance) {
                return false;
            }
            entries.retain(|_, entry| !expired(entry, now));
            !entries.is_empty()
        });
    }

    pub fn len(&self) -> usize {
        self.instances.values().map(HashMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn expired(entry: &Entry, now: u64) -> bool {
    now.saturating_sub(entry.last_used) >= IDLE_TTL_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Instance = Instance {
        pid: 10,
        start_time: 1,
    };
    const B: Instance = Instance {
        pid: 11,
        start_time: 1,
    };

    fn value(text: &str) -> SecretValue {
        let mut bytes = rbw::locked::Vec::new();
        bytes.extend(text.bytes());
        SecretValue::Plain(bytes)
    }

    fn secret(name: &str) -> SecretRef {
        SecretRef::parse(name).unwrap()
    }

    #[test]
    fn entries_belong_to_one_instance() {
        let mut cache = Cache::default();
        cache.insert(A, secret("token"), value("a"), 0);
        assert!(cache.get(A, &secret("token"), 1).is_some());
        assert!(cache.get(B, &secret("token"), 1).is_none());
        assert_eq!(
            cache.missing(B, &[secret("token")], 1),
            vec![secret("token")]
        );
    }

    #[test]
    fn missing_is_deduplicated_and_skips_cached() {
        let mut cache = Cache::default();
        cache.insert(A, secret("a"), value("1"), 0);
        let requested = [secret("a"), secret("b"), secret("b"), secret("c")];
        assert_eq!(
            cache.missing(A, &requested, 1),
            vec![secret("b"), secret("c")]
        );
    }

    #[test]
    fn idle_timer_resets_on_read() {
        let mut cache = Cache::default();
        cache.insert(A, secret("a"), value("1"), 0);
        assert!(cache.get(A, &secret("a"), IDLE_TTL_SECS - 1).is_some());
        // Read at TTL-1 reset the timer, so this read is within TTL of it.
        assert!(cache.get(A, &secret("a"), 2 * IDLE_TTL_SECS - 2).is_some());
        assert!(cache.get(A, &secret("a"), 3 * IDLE_TTL_SECS).is_none());
    }

    #[test]
    fn sweep_drops_idle_and_dead() {
        let mut cache = Cache::default();
        cache.insert(A, secret("old"), value("1"), 0);
        cache.insert(A, secret("new"), value("2"), IDLE_TTL_SECS);
        cache.insert(B, secret("x"), value("3"), IDLE_TTL_SECS);
        cache.sweep(IDLE_TTL_SECS + 1, |instance| instance == A);
        assert_eq!(cache.len(), 1);
        assert!(cache.get(A, &secret("new"), IDLE_TTL_SECS + 1).is_some());
    }
}
