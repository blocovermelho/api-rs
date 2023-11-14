use std::{collections::HashMap, hash::Hash};

use tokio::sync::{
    oneshot::{channel, Receiver, Sender},
    Mutex,
};

pub type OneshotBackend<K, T> = HashMap<K, DefferedOneshotChannel<T>>;
pub type DefferedOneshotChannel<T> = (Option<Sender<T>>, Option<Receiver<T>>);

fn has_sender<T>(channel: &DefferedOneshotChannel<T>) -> bool {
    channel.0.is_some()
}

fn has_receiver<T>(channel: &DefferedOneshotChannel<T>) -> bool {
    channel.1.is_some()
}

fn unset_receiver<K, T>(backing: &mut OneshotBackend<K, T>, k: K) -> Option<Receiver<T>>
where
    K: Eq + Hash,
{
    if let Some(deffered) = backing.remove(&k) {
        if has_sender(&deffered) {
            backing.insert(k, (deffered.0, None));
        }

        deffered.1
    } else {
        None
    }
}

fn unset_sender<K, T>(backing: &mut OneshotBackend<K, T>, k: K) -> Option<Sender<T>>
where
    K: Eq + Hash,
{
    if let Some(deffered) = backing.remove(&k) {
        if has_receiver(&deffered) {
            backing.insert(k, (None, deffered.1));
        }

        deffered.0
    } else {
        None
    }
}

/// A Thread-safe Bus backed by a [One-shot Channel](`tokio::sync::oneshot::channel`)
pub struct OneshotBus<K, T>
where
    K: Eq + Hash,
{
    inner: Mutex<OneshotBackend<K, T>>,
}

impl<K, T> OneshotBus<K, T>
where
    K: Eq + Hash,
{
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub async fn send(&self, k: K, v: T) -> Result<(), T> {
        let sender = self.get_sender(k).await;

        return match sender {
            Some(s) => s.send(v),
            None => Err(v),
        };
    }

    pub async fn recv(&self, k: K) -> Result<T, ()> {
        let receiver = self.get_receiver(k).await;

        return match receiver {
            Some(r) => r.await.or(Err(())),
            None => Err(()),
        };
    }

    async fn get_receiver(&self, k: K) -> Option<Receiver<T>> {
        let mut data = self.inner.lock().await;

        let deferred: &DefferedOneshotChannel<T> = data.get(&k).unwrap_or(&(None, None));

        let thisside = has_receiver(&deferred);
        let otherside = has_sender(&deferred);

        return if !thisside && !otherside {
            let (s, r) = channel();
            data.insert(k, (Some(s), None));

            Some(r)
        } else if thisside && !otherside {
            unset_receiver(&mut data, k)
        } else {
            None
        };
    }

    async fn get_sender(&self, k: K) -> Option<Sender<T>> {
        let mut data = self.inner.lock().await;

        let deferred: &DefferedOneshotChannel<T> = data.get(&k).unwrap_or(&(None, None));

        let thisside = has_sender(&deferred);
        let otherside = has_receiver(&deferred);

        return if !thisside && !otherside {
            let (s, r) = channel();
            data.insert(k, (None, Some(r)));
            Some(s)
        } else if thisside && !otherside {
            unset_sender(&mut data, k)
        } else {
            None
        };
    }
}
