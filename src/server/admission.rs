use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use dashmap::DashMap;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// RAII admission token for one accepted server connection.
///
/// The permit and per-IP guard are intentionally kept together so all server
/// listeners release their overload protections through the same drop path.
pub(super) struct AdmissionGuard {
    _permit: OwnedSemaphorePermit,
    _per_ip: Option<PerIpGuard>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AdmissionRejection {
    GlobalLimit,
    PerIpLimit { limit: u32 },
}

struct PerIpGuard {
    counter: Arc<AtomicU32>,
    map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    addr: IpAddr,
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        let previous = self.counter.fetch_sub(1, Ordering::AcqRel);
        if previous == 1 {
            let counter = Arc::clone(&self.counter);
            self.map.remove_if(&self.addr, |_, current| {
                Arc::ptr_eq(current, &counter) && current.load(Ordering::Acquire) == 0
            });
        }
    }
}

pub(super) fn admit_connection(
    semaphore: &Arc<Semaphore>,
    per_ip_map: &Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    addr: IpAddr,
    max_per_ip: Option<u32>,
) -> Result<AdmissionGuard, AdmissionRejection> {
    let per_ip = if let Some(limit) = max_per_ip {
        Some(try_acquire_per_ip(per_ip_map, addr, limit)?)
    } else {
        None
    };

    let permit = Arc::clone(semaphore)
        .try_acquire_owned()
        .map_err(|_| AdmissionRejection::GlobalLimit)?;

    Ok(AdmissionGuard {
        _permit: permit,
        _per_ip: per_ip,
    })
}

fn try_acquire_per_ip(
    map: &Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    addr: IpAddr,
    limit: u32,
) -> Result<PerIpGuard, AdmissionRejection> {
    let counter = Arc::clone(
        map.entry(addr)
            .or_insert_with(|| Arc::new(AtomicU32::new(0)))
            .value(),
    );

    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= limit {
            return Err(AdmissionRejection::PerIpLimit { limit });
        }
        match counter.compare_exchange_weak(
            current,
            current.saturating_add(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                return Ok(PerIpGuard {
                    counter,
                    map: Arc::clone(map),
                    addr,
                });
            }
            Err(updated) => current = updated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{admit_connection, AdmissionRejection, PerIpGuard};
    use dashmap::DashMap;
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::{
            atomic::{AtomicU32, Ordering},
            Arc,
        },
    };
    use tokio::sync::Semaphore;

    #[test]
    fn admission_releases_per_ip_slot_and_removes_empty_entry() -> Result<(), &'static str> {
        let semaphore = Arc::new(Semaphore::new(1));
        let map = Arc::new(DashMap::new());
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);

        let guard = admit_connection(&semaphore, &map, addr, Some(1))
            .map_err(|_| "admission should succeed")?;

        assert_eq!(
            map.get(&addr).map(|count| count.load(Ordering::Acquire)),
            Some(1)
        );
        assert_eq!(semaphore.available_permits(), 0);

        drop(guard);

        assert!(map.get(&addr).is_none());
        assert_eq!(semaphore.available_permits(), 1);
        Ok(())
    }

    #[test]
    fn admission_rejects_per_ip_limit_without_taking_global_permit() -> Result<(), &'static str> {
        let semaphore = Arc::new(Semaphore::new(2));
        let map = Arc::new(DashMap::new());
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let first = admit_connection(&semaphore, &map, addr, Some(1))
            .map_err(|_| "first admission should succeed")?;

        assert!(matches!(
            admit_connection(&semaphore, &map, addr, Some(1)),
            Err(AdmissionRejection::PerIpLimit { limit: 1 })
        ));
        assert_eq!(semaphore.available_permits(), 1);

        drop(first);
        Ok(())
    }

    #[test]
    fn stale_per_ip_guard_does_not_remove_recreated_counter() -> Result<(), &'static str> {
        let map = Arc::new(DashMap::new());
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let stale_counter = Arc::new(AtomicU32::new(1));
        let active_counter = Arc::new(AtomicU32::new(1));
        map.insert(addr, Arc::clone(&active_counter));

        drop(PerIpGuard {
            counter: stale_counter,
            map: Arc::clone(&map),
            addr,
        });

        let Some(current) = map.get(&addr) else {
            return Err("active counter must remain");
        };
        assert!(Arc::ptr_eq(current.value(), &active_counter));
        assert_eq!(active_counter.load(Ordering::Acquire), 1);
        Ok(())
    }

    #[test]
    fn per_ip_guard_keeps_reacquired_counter() -> Result<(), &'static str> {
        let map = Arc::new(DashMap::new());
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let counter = Arc::new(AtomicU32::new(1));
        map.insert(addr, Arc::clone(&counter));

        counter.store(2, Ordering::Release);
        drop(PerIpGuard {
            counter: Arc::clone(&counter),
            map: Arc::clone(&map),
            addr,
        });

        let Some(current) = map.get(&addr) else {
            return Err("reacquired counter must remain");
        };
        assert!(Arc::ptr_eq(current.value(), &counter));
        assert_eq!(counter.load(Ordering::Acquire), 1);
        Ok(())
    }
}
