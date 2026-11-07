//! Change notifications for live WebSocket connections, routed by account.
//!
//! In-process only: with several server instances behind a load balancer, a
//! connection hears about writes made through its own instance. Clients still
//! sync on reconnect and on focus, so a missed notification only delays a sync.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::broadcast;

/// Enough for a burst of writes. A connection that falls further behind is
/// told to resync every vault instead.
const CHANNEL_CAPACITY: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    VaultChanged { vault_id: String, revision: u64 },
    MembershipChanged { vault_id: String },
    SessionRevoked { device_id: String },
    AccountDeleted,
}

#[derive(Default)]
pub struct Events {
    accounts: Mutex<HashMap<String, broadcast::Sender<Event>>>,
}

impl Events {
    pub fn subscribe(&self, account_id: &str) -> broadcast::Receiver<Event> {
        self.lock()
            .entry(account_id.to_owned())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .subscribe()
    }

    /// Delivers to the account's open connections, if it has any.
    pub fn send(&self, account_id: &str, event: Event) {
        let mut accounts = self.lock();
        if let Some(sender) = accounts.get(account_id)
            && sender.send(event).is_err()
        {
            accounts.remove(account_id);
        }
    }

    /// Drops channels whose connections have all closed.
    pub fn prune(&self) {
        self.lock().retain(|_, sender| sender.receiver_count() > 0);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, broadcast::Sender<Event>>> {
        self.accounts.lock().expect("events lock poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn routes_events_by_account() {
        let events = Events::default();
        let mut alice = events.subscribe("alice");
        let mut alice_phone = events.subscribe("alice");
        let mut bob = events.subscribe("bob");

        events.send("alice", Event::AccountDeleted);
        assert_eq!(alice.recv().await.unwrap(), Event::AccountDeleted);
        assert_eq!(alice_phone.recv().await.unwrap(), Event::AccountDeleted);
        assert!(bob.try_recv().is_err());

        events.send("nobody", Event::AccountDeleted);
        drop(bob);
        events.prune();
        assert_eq!(events.lock().len(), 1);
        drop((alice, alice_phone));
        events.send("alice", Event::AccountDeleted);
        assert!(events.lock().is_empty());
    }
}
