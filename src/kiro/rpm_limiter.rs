// Copyright (c) 2026 Harllan He. Licensed under MIT.
//! Per-account RPM 限流器（滑动窗口）
//!
//! 与 `model::rpm::RpmTracker`（只统计、供 admin 仪表盘读取）不同，
//! 本模块是**真限流闸门**：在选号瞬间预占（record-on-select），
//! 让飞行中的请求也计入窗口，避免瞬时超发把单账号打到 AWS 429。
//!
//! 维度：
//! - per-account（按 credential id）：主闸门
//! - global（所有账号之和）：兜底
//!
//! 窗口：滑动 60 秒。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// 滑动窗口大小（秒）
const WINDOW_SECS: u64 = 60;

/// 单维度时间戳队列
#[derive(Default)]
struct WindowQueue {
    timestamps: Vec<Instant>,
}

impl WindowQueue {
    /// 清理过期条目，返回窗口内计数
    fn count(&mut self, now: Instant) -> u64 {
        let cutoff = now - std::time::Duration::from_secs(WINDOW_SECS);
        let pos = self.timestamps.partition_point(|t| *t < cutoff);
        if pos > 0 {
            self.timestamps.drain(..pos);
        }
        self.timestamps.len() as u64
    }

    fn record(&mut self, now: Instant) {
        self.timestamps.push(now);
    }
}

/// RPM 限流器
///
/// 线程安全。内存开销极小：每个请求一个 Instant（8 字节），60 秒后自动清理。
pub struct RpmLimiter {
    inner: Mutex<RpmLimiterInner>,
}

#[derive(Default)]
struct RpmLimiterInner {
    by_credential: HashMap<u64, WindowQueue>,
    global: WindowQueue,
}

impl RpmLimiter {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RpmLimiterInner::default()),
        }
    }

    /// 查询某账号当前 60s 窗口内的请求数
    pub fn credential_rpm(&self, credential_id: u64) -> u64 {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        inner
            .by_credential
            .get_mut(&credential_id)
            .map(|q| q.count(now))
            .unwrap_or(0)
    }

    /// 查询当前全局 60s 窗口内的请求数
    pub fn global_rpm(&self) -> u64 {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        inner.global.count(now)
    }

    /// 判断某账号是否仍在阈值内（< limit 表示可用）。
    /// limit=0 表示不限制该账号。
    pub fn credential_under_limit(&self, credential_id: u64, limit: u64) -> bool {
        if limit == 0 {
            return true;
        }
        self.credential_rpm(credential_id) < limit
    }

    /// 判断全局是否仍在阈值内（< limit 表示可用）。limit=0 表示不限制。
    pub fn global_under_limit(&self, limit: u64) -> bool {
        if limit == 0 {
            return true;
        }
        self.global_rpm() < limit
    }

    /// 预占：在选号成功后立即记录一次（per-account + global 同时记）。
    pub fn record(&self, credential_id: u64) {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        inner
            .by_credential
            .entry(credential_id)
            .or_default()
            .record(now);
        inner.global.record(now);
    }
}

impl Default for RpmLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_under_limit_zero_means_unlimited() {
        let l = RpmLimiter::new();
        for _ in 0..100 {
            l.record(1);
        }
        assert!(l.credential_under_limit(1, 0));
        assert!(l.global_under_limit(0));
    }

    #[test]
    fn test_credential_limit_blocks_after_threshold() {
        let l = RpmLimiter::new();
        // 记录 8 次，阈值 8 → 第 9 次应被拦（8 < 8 为 false）
        for _ in 0..8 {
            l.record(1);
        }
        assert_eq!(l.credential_rpm(1), 8);
        assert!(!l.credential_under_limit(1, 8));
        // 另一个账号不受影响
        assert!(l.credential_under_limit(2, 8));
    }

    #[test]
    fn test_global_limit() {
        let l = RpmLimiter::new();
        l.record(1);
        l.record(2);
        l.record(3);
        assert_eq!(l.global_rpm(), 3);
        assert!(l.global_under_limit(4));
        assert!(!l.global_under_limit(3));
    }

    #[test]
    fn test_global_sums_all_credentials() {
        let l = RpmLimiter::new();
        for _ in 0..5 {
            l.record(1);
        }
        for _ in 0..5 {
            l.record(2);
        }
        assert_eq!(l.credential_rpm(1), 5);
        assert_eq!(l.credential_rpm(2), 5);
        assert_eq!(l.global_rpm(), 10);
    }
}
