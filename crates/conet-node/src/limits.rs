//! Per-IP admission (requirement R9): concurrent connections and a request token bucket.
//! Other nodes forward everyone's traffic, so known node IPs get a much higher connection cap
//! and no rate limit; everything else is treated as a client.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct IpPolicy {
    pub client_max_conns: u32,
    pub node_max_conns: u32,
    /// Requests per second refilled into a client's bucket.
    pub client_rate: f64,
    pub client_burst: f64,
}

impl Default for IpPolicy {
    fn default() -> Self {
        Self {
            client_max_conns: 64,
            node_max_conns: 4096,
            client_rate: 20.0,
            client_burst: 60.0,
        }
    }
}

#[derive(Default)]
struct Inner {
    conns: HashMap<IpAddr, u32>,
    buckets: HashMap<IpAddr, (f64, Instant)>,
}

pub struct IpLimiter {
    policy: IpPolicy,
    inner: Mutex<Inner>,
}

/// Held while a connection is open; releases its slot on drop.
pub struct ConnSlot {
    ip: IpAddr,
    limiter: Arc<IpLimiter>,
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        let mut g = self.limiter.inner.lock().expect("limiter");
        if let Some(c) = g.conns.get_mut(&self.ip) {
            *c -= 1;
            if *c == 0 {
                g.conns.remove(&self.ip);
            }
        }
    }
}

impl IpLimiter {
    pub fn new(policy: IpPolicy) -> Arc<Self> {
        Arc::new(Self {
            policy,
            inner: Mutex::new(Inner::default()),
        })
    }

    /// Admit a new connection: a free connection slot and (for clients) one token.
    pub fn admit(self: &Arc<Self>, ip: IpAddr, is_node: bool) -> Option<ConnSlot> {
        let mut g = self.inner.lock().expect("limiter");
        let cap = if is_node {
            self.policy.node_max_conns
        } else {
            self.policy.client_max_conns
        };
        let open = g.conns.get(&ip).copied().unwrap_or(0);
        if open >= cap {
            return None;
        }
        if !is_node {
            if g.buckets.len() > 200_000 {
                // Forget idle buckets rather than grow without bound.
                let now = Instant::now();
                g.buckets
                    .retain(|_, (_, t)| now.duration_since(*t).as_secs() < 60);
            }
            let (rate, burst) = (self.policy.client_rate, self.policy.client_burst);
            let now = Instant::now();
            let b = g.buckets.entry(ip).or_insert((burst, now));
            b.0 = (b.0 + now.duration_since(b.1).as_secs_f64() * rate).min(burst);
            b.1 = now;
            if b.0 < 1.0 {
                return None;
            }
            b.0 -= 1.0;
        }
        *g.conns.entry(ip).or_insert(0) += 1;
        Some(ConnSlot {
            ip,
            limiter: self.clone(),
        })
    }

    pub fn open_connections(&self, ip: IpAddr) -> u32 {
        self.inner
            .lock()
            .expect("limiter")
            .conns
            .get(&ip)
            .copied()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_connections_and_rate() {
        let l = IpLimiter::new(IpPolicy {
            client_max_conns: 2,
            node_max_conns: 3,
            client_rate: 0.0,
            client_burst: 3.0,
        });
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let a = l.admit(ip, false).unwrap();
        let _b = l.admit(ip, false).unwrap();
        assert!(l.admit(ip, false).is_none(), "connection cap");
        drop(a);
        let _c = l.admit(ip, false).unwrap();
        assert_eq!(l.open_connections(ip), 2);
        drop(_c);
        assert!(
            l.admit(ip, false).is_none(),
            "bucket empty after 3 requests"
        );
        // nodes: no rate limit, higher cap
        let n: IpAddr = "198.51.100.9".parse().unwrap();
        let s: Vec<_> = (0..3).map(|_| l.admit(n, true).unwrap()).collect();
        assert!(l.admit(n, true).is_none());
        drop(s);
        assert_eq!(l.open_connections(n), 0);
    }
}
