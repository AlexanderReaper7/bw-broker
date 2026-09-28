//! Secrets approved per requesting instance.
//!
//! An entry is the approval itself: nothing is written to disk. It is dropped when its instance exits or after `IDLE_TTL_SECS` without being read by that instance.

use crate::process::Instance;
use crate::secret_ref::SecretRef;
use crate::vault::SecretValue;
use std::collections::HashMap;

pub const IDLE_TTL_SECS: u64 = 15 * 60;

/// What an approval allows. `Read` returns the value to the requester; `Type` only has the agent type it. A `Read` approval also covers `Type`, since a requester that has the value can type it itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Grant {
    Read,
    Type,
}

impl Grant {
    fn covers(self, wanted: Grant) -> bool {
        self == Grant::Read || wanted == Grant::Type
    }
}

struct Entry {
    value: SecretValue,
    grant: Grant,
    last_used: u64,
}

#[derive(Default)]
pub struct Cache {
    instances: HashMap<Instance, HashMap<SecretRef, Entry>>,
}

impl Cache {
    /// The requested secrets this instance has no live entry for that covers `grant`, in request order and without duplicates.
    pub fn missing(
        &self,
        instance: Instance,
        secrets: &[SecretRef],
        grant: Grant,
        now: u64,
    ) -> Vec<SecretRef> {
        let cached = self.instances.get(&instance);
        let mut missing: Vec<SecretRef> = Vec::new();
        for secret in secrets {
            let live = cached
                .and_then(|entries| entries.get(secret))
                .is_some_and(|entry| !expired(entry, now) && entry.grant.covers(grant));
            if !live && !missing.contains(secret) {
                missing.push(secret.clone());
            }
        }
        missing
    }

    /// Stores a freshly approved value. A live `Read` approval already held for the same secret is kept, so approving a `Type` never takes a `Read` away.
    pub fn insert(
        &mut self,
        instance: Instance,
        secret: SecretRef,
        value: SecretValue,
        grant: Grant,
        now: u64,
    ) {
        let entries = self.instances.entry(instance).or_default();
        let grant = match entries.get(&secret) {
            Some(old) if !expired(old, now) && old.grant == Grant::Read => Grant::Read,
            _ => grant,
        };
        entries.insert(
            secret,
            Entry {
                value,
                grant,
                last_used: now,
            },
        );
    }

    /// Reads an entry and resets its idle timer. Expired entries, and entries whose approval does not cover `grant`, read as absent.
    pub fn get(
        &mut self,
        instance: Instance,
        secret: &SecretRef,
        grant: Grant,
        now: u64,
    ) -> Option<&SecretValue> {
        let entry = self.instances.get_mut(&instance)?.get_mut(secret)?;
        if expired(entry, now) || !entry.grant.covers(grant) {
            return None;
        }
        entry.last_used = now;
        Some(&entry.value)
    }

    /// Drops the instance's entries for `secrets`, or all of them when `secrets` is empty. Returns how many live entries it dropped. Dropping zeroes the value.
    pub fn forget(&mut self, instance: Instance, secrets: &[SecretRef], now: u64) -> usize {
        let Some(entries) = self.instances.get_mut(&instance) else {
            return 0;
        };
        let mut forgotten = 0;
        entries.retain(|secret, entry| {
            let keep = !secrets.is_empty() && !secrets.contains(secret);
            if !keep && !expired(entry, now) {
                forgotten += 1;
            }
            keep
        });
        if entries.is_empty() {
            self.instances.remove(&instance);
        }
        forgotten
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
        cache.insert(A, secret("token"), value("a"), Grant::Read, 0);
        assert!(cache.get(A, &secret("token"), Grant::Read, 1).is_some());
        assert!(cache.get(B, &secret("token"), Grant::Read, 1).is_none());
        assert_eq!(
            cache.missing(B, &[secret("token")], Grant::Read, 1),
            vec![secret("token")]
        );
    }

    #[test]
    fn missing_is_deduplicated_and_skips_cached() {
        let mut cache = Cache::default();
        cache.insert(A, secret("a"), value("1"), Grant::Read, 0);
        let requested = [secret("a"), secret("b"), secret("b"), secret("c")];
        assert_eq!(
            cache.missing(A, &requested, Grant::Read, 1),
            vec![secret("b"), secret("c")]
        );
    }

    #[test]
    fn idle_timer_resets_on_read() {
        let mut cache = Cache::default();
        cache.insert(A, secret("a"), value("1"), Grant::Read, 0);
        assert!(cache
            .get(A, &secret("a"), Grant::Read, IDLE_TTL_SECS - 1)
            .is_some());
        // Read at TTL-1 reset the timer, so this read is within TTL of it.
        assert!(cache
            .get(A, &secret("a"), Grant::Read, 2 * IDLE_TTL_SECS - 2)
            .is_some());
        assert!(cache
            .get(A, &secret("a"), Grant::Read, 3 * IDLE_TTL_SECS)
            .is_none());
    }

    #[test]
    fn forget_named_leaves_the_rest() {
        let mut cache = Cache::default();
        cache.insert(A, secret("a"), value("1"), Grant::Read, 0);
        cache.insert(A, secret("b"), value("2"), Grant::Read, 0);
        cache.insert(B, secret("a"), value("3"), Grant::Read, 0);
        assert_eq!(cache.forget(A, &[secret("a"), secret("unknown")], 1), 1);
        assert!(cache.get(A, &secret("a"), Grant::Read, 1).is_none());
        assert!(cache.get(A, &secret("b"), Grant::Read, 1).is_some());
        assert!(cache.get(B, &secret("a"), Grant::Read, 1).is_some());
    }

    #[test]
    fn forget_all_is_per_instance_and_skips_expired_in_count() {
        let mut cache = Cache::default();
        cache.insert(A, secret("old"), value("1"), Grant::Read, 0);
        cache.insert(A, secret("new"), value("2"), Grant::Read, IDLE_TTL_SECS);
        cache.insert(B, secret("x"), value("3"), Grant::Read, IDLE_TTL_SECS);
        assert_eq!(cache.forget(A, &[], IDLE_TTL_SECS + 1), 1);
        assert_eq!(cache.len(), 1);
        assert!(cache
            .get(B, &secret("x"), Grant::Read, IDLE_TTL_SECS + 1)
            .is_some());
        assert_eq!(cache.forget(A, &[], IDLE_TTL_SECS + 1), 0);
    }

    #[test]
    fn sweep_drops_idle_and_dead() {
        let mut cache = Cache::default();
        cache.insert(A, secret("old"), value("1"), Grant::Read, 0);
        cache.insert(A, secret("new"), value("2"), Grant::Read, IDLE_TTL_SECS);
        cache.insert(B, secret("x"), value("3"), Grant::Read, IDLE_TTL_SECS);
        cache.sweep(IDLE_TTL_SECS + 1, |instance| instance == A);
        assert_eq!(cache.len(), 1);
        assert!(cache
            .get(A, &secret("new"), Grant::Read, IDLE_TTL_SECS + 1)
            .is_some());
    }

    #[test]
    fn type_approval_does_not_allow_read() {
        let mut cache = Cache::default();
        cache.insert(A, secret("pw"), value("1"), Grant::Type, 0);
        assert!(cache.get(A, &secret("pw"), Grant::Type, 1).is_some());
        assert!(cache.get(A, &secret("pw"), Grant::Read, 1).is_none());
        assert_eq!(
            cache.missing(A, &[secret("pw")], Grant::Read, 1),
            vec![secret("pw")]
        );
        assert!(cache.missing(A, &[secret("pw")], Grant::Type, 1).is_empty());
    }

    #[test]
    fn read_approval_allows_type_and_survives_a_type_approval() {
        let mut cache = Cache::default();
        cache.insert(A, secret("pw"), value("1"), Grant::Read, 0);
        assert!(cache.missing(A, &[secret("pw")], Grant::Type, 1).is_empty());
        cache.insert(A, secret("pw"), value("2"), Grant::Type, 2);
        assert!(cache.get(A, &secret("pw"), Grant::Read, 3).is_some());
    }
}
