use std::time::{Duration, Instant};

use lru::LruCache;
use quicfs_common::stat::Stat;

/// Configuration for the metadata cache.
#[derive(Clone)]
pub struct CacheConfig {
    pub max_entries: usize,
    pub pos_ttl: Duration,
    pub neg_ttl: Duration,
    pub dir_ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 8192,
            pos_ttl: Duration::from_millis(2000),
            neg_ttl: Duration::from_millis(500),
            dir_ttl: Duration::from_millis(1000),
        }
    }
}

/// A single cache entry: either a positive hit (we have the Stat) or a
/// negative hit (the path is known not to exist).
enum Entry {
    Found { stat: Stat, expires: Instant },
    NotFound { expires: Instant },
}

/// LRU metadata cache with per-entry TTL.
pub struct MetaCache {
    lru: LruCache<String, Entry>,
    cfg: CacheConfig,
}

impl MetaCache {
    pub fn new(cfg: CacheConfig) -> Self {
        Self {
            lru: LruCache::new(
                std::num::NonZeroUsize::new(cfg.max_entries)
                    .unwrap_or(std::num::NonZeroUsize::new(8192).unwrap()),
            ),
            cfg,
        }
    }

    /// Look up a path.  Returns `Some(Ok(stat))` on hit, `Some(Err(()))` on
    /// cached-negative, `None` on miss or expiry.
    pub fn get(&mut self, path: &str) -> Option<Result<Stat, ()>> {
        let now = Instant::now();
        // peek first to avoid taking a long-lived borrow before we might pop.
        let expired = match self.lru.peek(path) {
            None => return None,
            Some(Entry::Found { expires, .. }) => now >= *expires,
            Some(Entry::NotFound { expires }) => now >= *expires,
        };
        if expired {
            self.lru.pop(path);
            return None;
        }
        match self.lru.get(path) {
            Some(Entry::Found { stat, .. }) => Some(Ok(stat.clone())),
            Some(Entry::NotFound { .. }) => Some(Err(())),
            _ => None,
        }
    }

    /// Insert a positive result.
    pub fn insert(&mut self, path: String, stat: Stat, is_dir: bool) {
        let ttl = if is_dir {
            self.cfg.dir_ttl
        } else {
            self.cfg.pos_ttl
        };
        self.lru.put(
            path,
            Entry::Found {
                stat,
                expires: Instant::now() + ttl,
            },
        );
    }

    /// Insert a negative result (path does not exist).
    pub fn insert_negative(&mut self, path: String) {
        let expires = Instant::now() + self.cfg.neg_ttl;
        self.lru.put(path, Entry::NotFound { expires });
    }

    /// Invalidate a specific path and its parent directory.
    pub fn invalidate(&mut self, path: &str) {
        self.lru.pop(path);
        if let Some(parent) = std::path::Path::new(path).parent() {
            let p = parent.to_string_lossy();
            self.lru.pop(p.as_ref());
        }
    }

    /// Drop all entries (used on reconnect from fresh connection).
    pub fn clear(&mut self) {
        self.lru.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(ttl_ms: u64) -> CacheConfig {
        CacheConfig {
            max_entries: 16,
            pos_ttl: Duration::from_millis(ttl_ms),
            neg_ttl: Duration::from_millis(ttl_ms),
            dir_ttl: Duration::from_millis(ttl_ms),
        }
    }

    #[test]
    fn positive_hit_returns_stat() {
        let mut c = MetaCache::new(cfg(60_000));
        let mut s = Stat::default();
        s.size = 123;
        c.insert("/a".into(), s, false);
        match c.get("/a") {
            Some(Ok(got)) => assert_eq!(got.size, 123),
            other => panic!("expected positive hit, got {other:?}"),
        }
    }

    #[test]
    fn negative_hit_is_distinct_from_miss() {
        let mut c = MetaCache::new(cfg(60_000));
        assert!(c.get("/missing").is_none(), "unknown path is a miss");
        c.insert_negative("/missing".into());
        assert!(
            matches!(c.get("/missing"), Some(Err(()))),
            "now a cached-negative"
        );
    }

    #[test]
    fn entries_expire() {
        // ttl 0 → an entry is already expired by the time we read it.
        let mut c = MetaCache::new(cfg(0));
        c.insert("/a".into(), Stat::default(), false);
        assert!(
            c.get("/a").is_none(),
            "zero-TTL entry must read as expired/miss"
        );
        c.insert_negative("/b".into());
        assert!(c.get("/b").is_none(), "zero-TTL negative must expire too");
    }

    #[test]
    fn invalidate_drops_path_and_parent() {
        let mut c = MetaCache::new(cfg(60_000));
        c.insert("/dir".into(), Stat::default(), true);
        c.insert("/dir/file".into(), Stat::default(), false);
        c.invalidate("/dir/file"); // should drop the file AND its parent /dir
        assert!(c.get("/dir/file").is_none());
        assert!(
            c.get("/dir").is_none(),
            "parent dir entry must be invalidated too"
        );
    }

    #[test]
    fn clear_empties_everything() {
        let mut c = MetaCache::new(cfg(60_000));
        c.insert("/a".into(), Stat::default(), false);
        c.insert("/b".into(), Stat::default(), false);
        c.clear();
        assert!(c.get("/a").is_none());
        assert!(c.get("/b").is_none());
    }
}
