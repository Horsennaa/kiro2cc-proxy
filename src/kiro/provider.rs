// Copyright (c) 2026 Harllan He. Licensed under MIT.
//! Kiro API Provider
//!
//! 核心组件，负责与 Kiro API 通信
//! 支持流式和非流式请求
//! 支持多账号故障转移和重试

use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HOST, HeaderMap, HeaderValue};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

use crate::http_client::{ProxyConfig, build_client};
use crate::kiro::machine_id;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::token_manager::{CallContext, MultiTokenManager};
use crate::model::config::TlsBackend;
use crate::model::rpm::RpmTracker;
use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// 每个账号的最大重试次数
const MAX_RETRIES_PER_CREDENTIAL: usize = 3;

/// 总重试次数硬上限（避免无限重试）
const MAX_TOTAL_RETRIES: usize = 9;

/// 每账号并发默认值（不撞上游限流的安全值）。
/// 实测（2026-06-03 阶梯压测）单 Kiro 账号在并发 6 时已 ~45% 成功率（开始大量 429），
/// 故每账号取保守的 5：低于撞墙拐点，给负载均衡摊不匀留余量。
/// 启动时可通过环境变量 KIRO_CONCURRENT_PER_ACCOUNT 覆盖；运行时可通过 admin API 热改。
const DEFAULT_CONCURRENT_PER_ACCOUNT: usize = 5;

/// 读取“每账号并发”：优先环境变量 KIRO_CONCURRENT_PER_ACCOUNT，非法/缺失时回退默认值
fn concurrent_per_account() -> usize {
    std::env::var("KIRO_CONCURRENT_PER_ACCOUNT")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(DEFAULT_CONCURRENT_PER_ACCOUNT)
}

/// 首字节超时默认值（秒）。
/// 背景：build_client 的 reqwest .timeout() 是“总请求超时”（含整段响应流），硬编码 180s，
/// 无法区分“上游迟迟不吐第一个字节（卡死）”与“正常长流式响应”。实测上游偶发首字节延迟
/// 尖峰（frt 32s+）会让客户端 agent 干等到放弃（client_gone），表现为“调用无反应”。
/// 这里给主流式路径的 .send()（在响应头到达时 resolve，先于 body 流）单独加一层首字节超时，
/// 超时即视为本次尝试的瞬态失败，走既有重试/切账号逻辑，而不会误杀已经开始的长响应流。
const DEFAULT_FIRST_BYTE_TIMEOUT_SECS: u64 = 32;

/// 读取“首字节超时（秒）”：优先环境变量 KIRO_FIRST_BYTE_TIMEOUT_SECS。
/// 设为 0 表示禁用首字节超时（仅保留 build_client 的 180s 总超时）。
/// 非法/缺失时回退默认值。
fn first_byte_timeout_secs() -> u64 {
    std::env::var("KIRO_FIRST_BYTE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_FIRST_BYTE_TIMEOUT_SECS)
}

/// 计算初始并发配置，返回 (max, absolute_lock, per_account)：
/// 1. 若设置了 KIRO_MAX_CONCURRENT（绝对值，逃生口）→ 直接采用，锁定不随账号数/热改变化
/// 2. 否则 max = 每账号并发 × 可用账号数；运行时可随热加账号或 admin 改每账号值而 resize
///
/// account_count 传入 available_count()（非禁用账号数）。
fn initial_concurrency_config(account_count: usize) -> (usize, bool, usize) {
    let per = concurrent_per_account();
    // 绝对值逃生口优先：压测/排障时可强制指定，忽略账号数，且锁定不可热改
    if let Some(abs) = std::env::var("KIRO_MAX_CONCURRENT")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1)
    {
        return (abs, true, per);
    }
    let n = account_count.max(1); // 至少按 1 个账号算，避免空账号时上限为 0
    (per.saturating_mul(n).max(1), false, per)
}

/// 并发快照：metrics 端点与结构化日志共用的真实并发度读数
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct ConcurrencySnapshot {
    /// 并发上限（KIRO_MAX_CONCURRENT，与信号量初始 permit 数一致）
    pub max: usize,
    /// 当前在飞：已拿到名额、正在请求上游（= max - available）
    pub in_use: usize,
    /// 当前在信号量门口排队等待名额的请求数（自维护计数器）
    pub waiting: usize,
    /// 剩余可用名额
    pub available: usize,
}

/// 并发控制器：集中管理信号量 + 运行时可改的上限。
/// 所有读写均走该结构（共享 Arc），保证 provider 热路径与 admin 热改看到同一份状态。
///
/// resize 语义：
/// - 扩容：`add_permits(delta)`，立即生效，排队中的请求马上拿到新名额。
/// - 缩容：`forget_permits(delta)`，仅抑制未来发放，**不打断在飞请求**；
///   若当前 available 不足，剩余负值会随在飞请求陆续释放时被吸收，最终收敛到新上限。
pub struct ConcurrencyController {
    /// 并发控制信号量，限制同时发往上游的请求数
    semaphore: Arc<Semaphore>,
    /// 当前并发上限（= 信号量逻辑 permit 总数，运行时可变）
    max: AtomicUsize,
    /// 在信号量门口排队等待名额的请求数（自维护计数器，tokio 不原生暴露）
    waiting: Arc<AtomicUsize>,
    /// 每账号并发值（运行时可改；仅在未设 KIRO_MAX_CONCURRENT 绝对值时生效）
    per_account: AtomicUsize,
    /// 是否走绝对值锁定（KIRO_MAX_CONCURRENT 设置后，per_account 不再影响上限）
    absolute_lock: bool,
}

impl ConcurrencyController {
    /// 创建控制器。`per_account` 为启动时读取的每账号值，`absolute_lock` 表示是否由 KIRO_MAX_CONCURRENT 锁定。
    fn new(initial_max: usize, per_account: usize, absolute_lock: bool) -> Arc<Self> {
        Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(initial_max)),
            max: AtomicUsize::new(initial_max),
            waiting: Arc::new(AtomicUsize::new(0)),
            per_account: AtomicUsize::new(per_account.max(1)),
            absolute_lock,
        })
    }

    /// 读当前并发上限
    pub fn max(&self) -> usize {
        self.max.load(Ordering::Relaxed)
    }

    /// 读当前每账号并发值
    pub fn per_account(&self) -> usize {
        self.per_account.load(Ordering::Relaxed)
    }

    /// 是否被绝对值锁定（锁定时改 per_account 不会调整上限）
    pub fn is_absolute_lock(&self) -> bool {
        self.absolute_lock
    }

    /// 读当前并发快照（瞬时值）
    pub fn snapshot(&self) -> ConcurrencySnapshot {
        let max = self.max.load(Ordering::Relaxed);
        let available = self.semaphore.available_permits();
        ConcurrencySnapshot {
            max,
            in_use: max.saturating_sub(available),
            waiting: self.waiting.load(Ordering::Relaxed),
            available,
        }
    }

    /// 申请名额（cancel-safe）：进入等待前 +1 排队计数，拿到名额（或被取消）后由 guard 自动 -1。
    async fn acquire(&self) -> anyhow::Result<OwnedSemaphorePermit> {
        let guard = WaitingGuard::new(self.waiting.clone());
        let permit = self.semaphore.clone().acquire_owned().await?;
        drop(guard);
        Ok(permit)
    }

    /// 将并发上限调整为 `new_max`（扩容立即生效，缩容不打断在飞请求）。
    /// 返回 (old_max, new_max)。new_max 底为 1。
    fn resize_to(&self, new_max: usize) -> (usize, usize) {
        let new_max = new_max.max(1);
        let old_max = self.max.swap(new_max, Ordering::SeqCst);
        if new_max > old_max {
            self.semaphore.add_permits(new_max - old_max);
        } else if new_max < old_max {
            // forget_permits 只能回收当前 available 的部分；超出部分随在飞请求释放时被
            // “欠账”吸收（max 已下调，in_use 可能短暂 > max，快照会 saturating 到 0）。
            self.semaphore.forget_permits(old_max - new_max);
        }
        (old_max, new_max)
    }

    /// 重算并应用“按账号数 × 每账号”的上限（绝对值锁定时为 no-op）。
    /// `account_count` 传入当前可用账号数。返回 (old_max, new_max)。
    pub fn recompute_for_accounts(&self, account_count: usize) -> (usize, usize) {
        if self.absolute_lock {
            let m = self.max.load(Ordering::Relaxed);
            return (m, m);
        }
        let per = self.per_account.load(Ordering::Relaxed).max(1);
        let n = account_count.max(1);
        self.resize_to(per.saturating_mul(n))
    }

    /// 设置每账号并发值并立即按当前账号数 resize（运行时热改入口）。
    /// 绝对值锁定时返回 Err。返回 (old_max, new_max)。
    pub fn set_per_account(&self, per_account: usize, account_count: usize) -> anyhow::Result<(usize, usize)> {
        if self.absolute_lock {
            anyhow::bail!("当前由 KIRO_MAX_CONCURRENT 绝对值锁定，改每账号值无效；请先移除该环境变量");
        }
        let per = per_account.max(1);
        self.per_account.store(per, Ordering::Relaxed);
        Ok(self.recompute_for_accounts(account_count))
    }
}

/// 并发监控句柄：可克隆，供 admin /metrics 端点读取实时并发度。
/// 数据源与 provider 内部信号量完全一致（共享 Arc<ConcurrencyController>）。
#[derive(Clone)]
pub struct ConcurrencyMonitor {
    controller: Arc<ConcurrencyController>,
}

impl ConcurrencyMonitor {
    /// 读取当前并发快照（瞬时值）
    pub fn snapshot(&self) -> ConcurrencySnapshot {
        self.controller.snapshot()
    }

    /// 设置每账号并发值并立即 resize（运行时热改，无需重启）。
    /// 返回 (old_max, new_max)；绝对值锁定时返回 Err。
    pub fn set_per_account(&self, per_account: usize, account_count: usize) -> anyhow::Result<(usize, usize)> {
        self.controller.set_per_account(per_account, account_count)
    }

    /// 按当前账号数重算上限（热加/禁用账号后调用，即时跟随）。
    pub fn recompute_for_accounts(&self, account_count: usize) -> (usize, usize) {
        self.controller.recompute_for_accounts(account_count)
    }

    /// 当前每账号并发值
    pub fn per_account(&self) -> usize {
        self.controller.per_account()
    }

    /// 是否被 KIRO_MAX_CONCURRENT 绝对值锁定
    pub fn is_absolute_lock(&self) -> bool {
        self.controller.is_absolute_lock()
    }
}

/// 排队计数守卫：进入 acquire 等待前 +1，离开（拿到名额或 future 被取消）时 -1。
/// 用 Drop 保证 cancel-safe —— 客户端断连导致 await 被取消时计数器也能正确回退。
struct WaitingGuard(Arc<AtomicUsize>);

impl WaitingGuard {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        WaitingGuard(counter)
    }
}

impl Drop for WaitingGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Kiro API Provider
///
/// 核心组件，负责与 Kiro API 通信
/// 支持多账号故障转移和重试机制
pub struct KiroProvider {
    token_manager: Arc<MultiTokenManager>,
    /// 全局代理配置（用于账号无自定义代理时的回退）
    global_proxy: Option<ProxyConfig>,
    /// Client 缓存：key = effective proxy config, value = reqwest::Client
    /// 不同代理配置的账号使用不同的 Client，共享相同代理的账号复用 Client
    client_cache: Mutex<HashMap<Option<ProxyConfig>, Client>>,
    /// TLS 后端配置
    tls_backend: TlsBackend,
    /// 并发控制器（信号量 + 运行时可改上限 + 排队计数，共享 Arc）
    concurrency: Arc<ConcurrencyController>,
    /// RPM 追踪器（可选，用于记录账号维度的 RPM）
    rpm_tracker: Option<Arc<RpmTracker>>,
}

#[allow(dead_code)]
impl KiroProvider {
    /// 创建新的 KiroProvider 实例
    pub fn new(token_manager: Arc<MultiTokenManager>) -> Self {
        Self::with_proxy(token_manager, None)
    }

    /// 创建带代理配置的 KiroProvider 实例
    pub fn with_proxy(token_manager: Arc<MultiTokenManager>, proxy: Option<ProxyConfig>) -> Self {
        let tls_backend = token_manager.config().tls_backend;
        // 预热：构建全局代理对应的 Client
        let initial_client = build_client(proxy.as_ref(), 180, tls_backend)
            .expect("创建 HTTP 客户端失败");
        let mut cache = HashMap::new();
        cache.insert(proxy.clone(), initial_client);

        let account_count = token_manager.available_count();
        let (max_concurrent, absolute_lock, per_account) = initial_concurrency_config(account_count);
        tracing::info!(
            "并发上限 = {}（账号数={}，每账号={}，锁定={}，排队模式，超额请求等待名额；\
             绝对值覆盖 KIRO_MAX_CONCURRENT / 每账号 KIRO_CONCURRENT_PER_ACCOUNT，辐可经 admin API 热改）",
            max_concurrent,
            account_count,
            per_account,
            absolute_lock
        );

        Self {
            token_manager,
            global_proxy: proxy,
            client_cache: Mutex::new(cache),
            tls_backend,
            concurrency: ConcurrencyController::new(max_concurrent, per_account, absolute_lock),
            rpm_tracker: None,
        }
    }

    /// 设置 RPM 追踪器
    pub fn with_rpm_tracker(mut self, tracker: Arc<RpmTracker>) -> Self {
        self.rpm_tracker = Some(tracker);
        self
    }

    /// 获取并发监控句柄（可克隆，供 admin /metrics 与 热改端点共享同一控制器）
    pub fn concurrency_monitor(&self) -> ConcurrencyMonitor {
        ConcurrencyMonitor {
            controller: self.concurrency.clone(),
        }
    }

    /// 读取当前并发快照（瞬时值），用于结构化日志注入
    fn concurrency_snapshot(&self) -> ConcurrencySnapshot {
        self.concurrency.snapshot()
    }

    /// 申请并发名额：进入等待前 +1 排队计数，拿到名额（或被取消）后由 guard 自动 -1。
    /// 集中在 controller 处理排队埋点，两个调用点共用，cancel-safe。
    async fn acquire_permit(&self) -> anyhow::Result<OwnedSemaphorePermit> {
        self.concurrency.acquire().await
    }

    /// 根据账号的代理配置获取（或创建并缓存）对应的 reqwest::Client
    fn client_for(&self, credentials: &KiroCredentials) -> anyhow::Result<Client> {
        let effective = credentials.effective_proxy(self.global_proxy.as_ref());
        let mut cache = self.client_cache.lock();
        if let Some(client) = cache.get(&effective) {
            return Ok(client.clone());
        }
        let client = build_client(effective.as_ref(), 180, self.tls_backend)?;
        cache.insert(effective, client.clone());
        Ok(client)
    }

    /// 获取 token_manager 的引用
    pub fn token_manager(&self) -> &MultiTokenManager {
        &self.token_manager
    }

    /// 获取 API 基础 URL（使用 config 级 api_region）
    pub fn base_url(&self) -> String {
        format!(
            "https://q.{}.amazonaws.com/generateAssistantResponse",
            self.token_manager.config().effective_api_region()
        )
    }

    /// 获取 MCP API URL（使用 config 级 api_region）
    pub fn mcp_url(&self) -> String {
        format!(
            "https://q.{}.amazonaws.com/mcp",
            self.token_manager.config().effective_api_region()
        )
    }

    /// 获取 API 基础域名（使用 config 级 api_region）
    pub fn base_domain(&self) -> String {
        format!("q.{}.amazonaws.com", self.token_manager.config().effective_api_region())
    }

    /// 获取账号级 API 基础 URL
    fn base_url_for(&self, credentials: &KiroCredentials) -> String {
        format!(
            "https://q.{}.amazonaws.com/generateAssistantResponse",
            credentials.effective_api_region(self.token_manager.config())
        )
    }

    /// 获取账号级 MCP API URL
    fn mcp_url_for(&self, credentials: &KiroCredentials) -> String {
        format!(
            "https://q.{}.amazonaws.com/mcp",
            credentials.effective_api_region(self.token_manager.config())
        )
    }

    /// 获取账号级 API 基础域名
    fn base_domain_for(&self, credentials: &KiroCredentials) -> String {
        format!(
            "q.{}.amazonaws.com",
            credentials.effective_api_region(self.token_manager.config())
        )
    }

    /// 从请求体中提取模型信息
    ///
    /// 尝试解析 JSON 请求体，提取 conversationState.currentMessage.userInputMessage.modelId
    fn extract_model_from_request(request_body: &str) -> Option<String> {
        use serde_json::Value;

        let json: Value = serde_json::from_str(request_body).ok()?;

        // 尝试提取 conversationState.currentMessage.userInputMessage.modelId
        json.get("conversationState")?
            .get("currentMessage")?
            .get("userInputMessage")?
            .get("modelId")?
            .as_str()
            .map(|s| s.to_string())
    }

    /// 从请求体中提取 agentTaskType
    ///
    /// 提取 conversationState.agentTaskType，用于设置 x-amzn-kiro-agent-mode 请求头
    fn extract_agent_task_type_from_request(request_body: &str) -> &'static str {
        let Ok(json) = serde_json::from_str::<serde_json::Value>(request_body) else {
            return "vibe";
        };
        match json
            .get("conversationState")
            .and_then(|s| s.get("agentTaskType"))
            .and_then(|v| v.as_str())
        {
            Some("spectask") => "spectask",
            _ => "vibe",
        }
    }

    /// 提取 conversationState.agentContinuationId，用于 sticky cache 路由
    fn extract_continuation_id_from_request(request_body: &str) -> Option<String> {
        let json: serde_json::Value = serde_json::from_str(request_body).ok()?;
        json.get("conversationState")?
            .get("agentContinuationId")?
            .as_str()
            .map(|s| s.to_string())
    }

    /// 构建请求头
    ///
    /// # Arguments
    /// * `ctx` - API 调用上下文，包含账号和 token
    /// * `request_body` - 请求体，用于提取 agentTaskType
    fn build_headers(&self, ctx: &CallContext, request_body: &str) -> anyhow::Result<HeaderMap> {
        let config = self.token_manager.config();

        let machine_id = machine_id::generate_from_credentials(&ctx.credentials, config)
            .ok_or_else(|| anyhow::anyhow!("无法生成 machine_id，请检查凭证配置"))?;

        let kiro_version = &config.kiro_version;
        let os_name = &config.system_version;
        let node_version = &config.node_version;

        let x_amz_user_agent = format!("aws-sdk-js/1.0.27 KiroIDE-{}-{}", kiro_version, machine_id);

        let user_agent = format!(
            "aws-sdk-js/1.0.27 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererstreaming#1.0.27 m/E KiroIDE-{}-{}",
            os_name, node_version, kiro_version, machine_id
        );

        let agent_mode = Self::extract_agent_task_type_from_request(request_body);

        let mut headers = HeaderMap::new();

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            "x-amzn-codewhisperer-optout",
            HeaderValue::from_static("true"),
        );
        headers.insert("x-amzn-kiro-agent-mode", HeaderValue::from_static(agent_mode));
        headers.insert(
            "x-amz-user-agent",
            HeaderValue::from_str(&x_amz_user_agent).unwrap(),
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&user_agent).unwrap(),
        );
        headers.insert(HOST, HeaderValue::from_str(&self.base_domain_for(&ctx.credentials)).unwrap());
        headers.insert(
            "amz-sdk-invocation-id",
            HeaderValue::from_str(&Uuid::new_v4().to_string()).unwrap(),
        );
        headers.insert(
            "amz-sdk-request",
            HeaderValue::from_static("attempt=1; max=3"),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", ctx.token)).unwrap(),
        );
        Ok(headers)
    }

    /// 构建 MCP 请求头
    fn build_mcp_headers(&self, ctx: &CallContext) -> anyhow::Result<HeaderMap> {
        let config = self.token_manager.config();

        let machine_id = machine_id::generate_from_credentials(&ctx.credentials, config)
            .ok_or_else(|| anyhow::anyhow!("无法生成 machine_id，请检查凭证配置"))?;

        let kiro_version = &config.kiro_version;
        let os_name = &config.system_version;
        let node_version = &config.node_version;

        let x_amz_user_agent = format!("aws-sdk-js/1.0.27 KiroIDE-{}-{}", kiro_version, machine_id);

        let user_agent = format!(
            "aws-sdk-js/1.0.27 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererstreaming#1.0.27 m/E KiroIDE-{}-{}",
            os_name, node_version, kiro_version, machine_id
        );

        let mut headers = HeaderMap::new();

        // 按照严格顺序添加请求头
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert(
            "x-amz-user-agent",
            HeaderValue::from_str(&x_amz_user_agent).unwrap(),
        );
        headers.insert("user-agent", HeaderValue::from_str(&user_agent).unwrap());
        headers.insert("host", HeaderValue::from_str(&self.base_domain_for(&ctx.credentials)).unwrap());
        headers.insert(
            "amz-sdk-invocation-id",
            HeaderValue::from_str(&Uuid::new_v4().to_string()).unwrap(),
        );
        headers.insert(
            "amz-sdk-request",
            HeaderValue::from_static("attempt=1; max=3"),
        );
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", ctx.token)).unwrap(),
        );
        Ok(headers)
    }

    /// 发送非流式 API 请求
    ///
    /// 支持多账号故障转移：
    /// - 400 Bad Request: 直接返回错误，不计入账号失败
    /// - 401/403: 视为账号/权限问题，计入失败次数并允许故障转移
    /// - 402 MONTHLY_REQUEST_COUNT: 视为额度用尽，禁用账号并切换
    /// - 429/5xx/网络等瞬态错误: 重试但不禁用或切换账号（避免误把所有账号锁死）
    ///
    /// # Arguments
    /// * `request_body` - JSON 格式的请求体字符串
    ///
    /// # Returns
    /// 返回原始的 HTTP Response，不做解析
    pub async fn call_api(&self, request_body: &str, bound_ids: &[u64]) -> anyhow::Result<(reqwest::Response, u64, OwnedSemaphorePermit)> {
        self.call_api_with_retry(request_body, false, bound_ids).await
    }

    /// 发送流式 API 请求
    ///
    /// 支持多账号故障转移：
    /// - 400 Bad Request: 直接返回错误，不计入账号失败
    /// - 401/403: 视为账号/权限问题，计入失败次数并允许故障转移
    /// - 402 MONTHLY_REQUEST_COUNT: 视为额度用尽，禁用账号并切换
    /// - 429/5xx/网络等瞬态错误: 重试但不禁用或切换账号（避免误把所有账号锁死）
    ///
    /// # Arguments
    /// * `request_body` - JSON 格式的请求体字符串
    ///
    /// # Returns
    /// 返回原始的 HTTP Response，调用方负责处理流式数据
    pub async fn call_api_stream(&self, request_body: &str, bound_ids: &[u64]) -> anyhow::Result<(reqwest::Response, u64, OwnedSemaphorePermit)> {
        self.call_api_with_retry(request_body, true, bound_ids).await
    }

    /// 发送 MCP API 请求
    ///
    /// 用于 WebSearch 等工具调用
    ///
    /// # Arguments
    /// * `request_body` - JSON 格式的 MCP 请求体字符串
    ///
    /// # Returns
    /// 返回原始的 HTTP Response
    pub async fn call_mcp(&self, request_body: &str, bound_ids: &[u64]) -> anyhow::Result<(reqwest::Response, u64, OwnedSemaphorePermit)> {
        self.call_mcp_with_retry(request_body, bound_ids).await
    }

    /// 内部方法：带重试逻辑的 MCP API 调用
    async fn call_mcp_with_retry(&self, request_body: &str, bound_ids: &[u64]) -> anyhow::Result<(reqwest::Response, u64, OwnedSemaphorePermit)> {
        let permit = self.acquire_permit().await?;
        let total_credentials = self.token_manager.total_count();
        let max_retries = (total_credentials * MAX_RETRIES_PER_CREDENTIAL).min(MAX_TOTAL_RETRIES);
        let mut last_error: Option<anyhow::Error> = None;

        let continuation_id = Self::extract_continuation_id_from_request(request_body);

        for attempt in 0..max_retries {
            // 获取调用上下文（MCP 不涉及模型选择，但同样应用 sticky 路由）
            let ctx = match self.token_manager.acquire_context_sticky(None, bound_ids, continuation_id.as_deref()).await {
                Ok(c) => c,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };

            let url = self.mcp_url_for(&ctx.credentials);
            let headers = match self.build_mcp_headers(&ctx) {
                Ok(h) => h,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };

            // 发送请求
            let response = match self
                .client_for(&ctx.credentials)?
                .post(&url)
                .headers(headers)
                .body(request_body.to_string())
                .send()
                .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!(
                        "MCP 请求发送失败（尝试 {}/{}）: {}",
                        attempt + 1,
                        max_retries,
                        e
                    );
                    last_error = Some(e.into());
                    if attempt + 1 < max_retries {
                        sleep(Self::retry_delay(attempt)).await;
                    }
                    continue;
                }
            };

            let status = response.status();

            // 成功响应
            if status.is_success() {
                self.token_manager.report_success(ctx.id);
                if let Some(rpm) = &self.rpm_tracker {
                    rpm.record_credential(ctx.id);
                }
                return Ok((response, ctx.id, permit));
            }

            // 失败响应
            let body = response.text().await.unwrap_or_default();

            // 402 额度用尽
            if status.as_u16() == 402 && Self::is_monthly_request_limit(&body) {
                let has_available = self.token_manager.report_quota_exhausted(ctx.id);
                if !has_available {
                    anyhow::bail!("MCP 请求失败（所有账号已用尽）: {} {}", status, body);
                }
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                continue;
            }

            // 400 Bad Request
            if status.as_u16() == 400 {
                anyhow::bail!("MCP 请求失败: {} {}", status, body);
            }

            // 401/403 账号问题
            if matches!(status.as_u16(), 401 | 403) {
                let has_available = self.token_manager.report_failure(ctx.id);
                if !has_available {
                    anyhow::bail!("MCP 请求失败（所有账号已用尽）: {} {}", status, body);
                }
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                continue;
            }

            // 429 Too Many Requests - 限流：递增 success_count 让 Least-Used 算法轮转到下一个账号
            if status.as_u16() == 429 {
                tracing::warn!(
                    "MCP 请求失败（上游限流，切换账号重试，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );
                self.token_manager.report_throttled(ctx.id);
                self.token_manager.report_success(ctx.id);
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                if attempt + 1 < max_retries {
                    sleep(Self::retry_delay(attempt)).await;
                }
                continue;
            }

            // 408/5xx - 瞬态上游错误
            if status.as_u16() == 408 || status.is_server_error() {
                tracing::warn!(
                    "MCP 请求失败（上游瞬态错误，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                if attempt + 1 < max_retries {
                    sleep(Self::retry_delay(attempt)).await;
                }
                continue;
            }

            // 其他 4xx
            if status.is_client_error() {
                anyhow::bail!("MCP 请求失败: {} {}", status, body);
            }

            // 兜底
            last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
            if attempt + 1 < max_retries {
                sleep(Self::retry_delay(attempt)).await;
            }
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!("MCP 请求失败：已达到最大重试次数（{}次）", max_retries)
        }))
    }

    /// 内部方法：带重试逻辑的 API 调用
    ///
    /// 重试策略：
    /// - 每个账号最多重试 MAX_RETRIES_PER_CREDENTIAL 次
    /// - 总重试次数 = min(账号数量 × 每账号重试次数, MAX_TOTAL_RETRIES)
    /// - 硬上限 9 次，避免无限重试
    async fn call_api_with_retry(
        &self,
        request_body: &str,
        is_stream: bool,
        bound_ids: &[u64],
    ) -> anyhow::Result<(reqwest::Response, u64, OwnedSemaphorePermit)> {
        let permit = self.acquire_permit().await?;
        let total_credentials = self.token_manager.total_count();
        let max_retries = (total_credentials * MAX_RETRIES_PER_CREDENTIAL).min(MAX_TOTAL_RETRIES);
        let mut last_error: Option<anyhow::Error> = None;
        let api_type = if is_stream { "流式" } else { "非流式" };

        // 尝试从请求体中提取模型信息和会话 ID
        let model = Self::extract_model_from_request(request_body);
        let continuation_id = Self::extract_continuation_id_from_request(request_body);

        for attempt in 0..max_retries {
            // 获取调用上下文（优先路由到同一会话的缓存账号）
            let ctx = match self.token_manager.acquire_context_sticky(model.as_deref(), bound_ids, continuation_id.as_deref()).await {
                Ok(c) => c,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };

            let url = self.base_url_for(&ctx.credentials);
            let headers = match self.build_headers(&ctx, request_body) {
                Ok(h) => h,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };

            // 发送请求（首字节超时保护：仅 .send() 阶段，不影响后续 body 流式读取）
            let fb_timeout = first_byte_timeout_secs();
            let send_fut = self
                .client_for(&ctx.credentials)?
                .post(&url)
                .headers(headers)
                .body(request_body.to_string())
                .send();
            let send_result = if fb_timeout > 0 {
                match tokio::time::timeout(Duration::from_secs(fb_timeout), send_fut).await {
                    Ok(r) => r,
                    Err(_) => {
                        tracing::warn!(
                            "API 首字节超时（{}s 内上游未返回响应头，尝试 {}/{}），按瞬态网络错误重试",
                            fb_timeout,
                            attempt + 1,
                            max_retries
                        );
                        last_error = Some(anyhow::anyhow!(
                            "上游首字节超时：{}s 内未返回响应头",
                            fb_timeout
                        ));
                        if attempt + 1 < max_retries {
                            sleep(Self::retry_delay(attempt)).await;
                        }
                        continue;
                    }
                }
            } else {
                send_fut.await
            };
            let response = match send_result
            {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!(
                        "API 请求发送失败（尝试 {}/{}）: {}",
                        attempt + 1,
                        max_retries,
                        e
                    );
                    // 网络错误通常是上游/链路瞬态问题，不应导致"禁用账号"或"切换账号"
                    // （否则一段时间网络抖动会把所有账号都误禁用，需要重启才能恢复）
                    last_error = Some(e.into());
                    if attempt + 1 < max_retries {
                        sleep(Self::retry_delay(attempt)).await;
                    }
                    continue;
                }
            };

            let status = response.status();

            // 成功响应
            if status.is_success() {
                self.token_manager.report_success(ctx.id);
                if let Some(rpm) = &self.rpm_tracker {
                    rpm.record_credential(ctx.id);
                }
                // 仅在有竞争时（名额满/有排队）记录成功路径的并发快照，
                // 避免正常负载下翻倍热路径日志量（415MB 生产机敏感）。
                let conc = self.concurrency_snapshot();
                if conc.waiting > 0 || conc.in_use >= conc.max {
                    tracing::info!(
                        evt = "upstream_success",
                        status_code = status.as_u16(),
                        cred = ctx.id,
                        conc_in_use = conc.in_use,
                        conc_wait = conc.waiting,
                        conc_max = conc.max,
                        "上游成功（高并发）"
                    );
                }
                return Ok((response, ctx.id, permit));
            }

            // 失败响应：读取 body 用于日志/错误信息
            let body = response.text().await.unwrap_or_default();

            // 402 Payment Required 且额度用尽：禁用账号并故障转移
            if status.as_u16() == 402 && Self::is_monthly_request_limit(&body) {
                tracing::warn!(
                    "API 请求失败（额度已用尽，禁用账号并切换，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );

                let has_available = self.token_manager.report_quota_exhausted(ctx.id);
                if !has_available {
                    anyhow::bail!(
                        "{} API 请求失败（所有账号已用尽）: {} {}",
                        api_type,
                        status,
                        body
                    );
                }

                last_error = Some(anyhow::anyhow!(
                    "{} API 请求失败: {} {}",
                    api_type,
                    status,
                    body
                ));
                continue;
            }

            // 400 Bad Request - 请求问题，重试/切换账号无意义
            if status.as_u16() == 400 {
                anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
            }

            // 401/403 - 更可能是账号/权限问题：计入失败并允许故障转移
            if matches!(status.as_u16(), 401 | 403) {
                tracing::warn!(
                    "API 请求失败（可能为账号错误，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );

                let has_available = self.token_manager.report_failure(ctx.id);
                if !has_available {
                    anyhow::bail!(
                        "{} API 请求失败（所有账号已用尽）: {} {}",
                        api_type,
                        status,
                        body
                    );
                }

                last_error = Some(anyhow::anyhow!(
                    "{} API 请求失败: {} {}",
                    api_type,
                    status,
                    body
                ));
                continue;
            }

            // 429 Too Many Requests - 限流：递增 success_count 让 Least-Used 算法轮转到下一个账号
            if status.as_u16() == 429 {
                let conc = self.concurrency_snapshot();
                tracing::warn!(
                    evt = "upstream_throttled",
                    status_code = 429,
                    cred = ctx.id,
                    attempt = attempt + 1,
                    max_retries = max_retries,
                    conc_in_use = conc.in_use,
                    conc_wait = conc.waiting,
                    conc_max = conc.max,
                    "API 请求失败（上游限流）: {} {}",
                    status,
                    body
                );
                self.token_manager.report_throttled(ctx.id);
                // 递增 success_count，使 balanced 模式下一次 acquire_context 选择其他账号
                self.token_manager.report_success(ctx.id);
                last_error = Some(anyhow::anyhow!(
                    "{} API 请求失败: {} {}",
                    api_type,
                    status,
                    body
                ));
                // 限流专用退避：比普通瞬态错误更长，避免单账号场景下
                // 立即重试空转放大（一次真实限流被放大成多条 429 日志）
                if attempt + 1 < max_retries {
                    sleep(Self::throttle_delay(attempt)).await;
                }
                continue;
            }

            // 408/5xx - 瞬态上游错误：重试但不禁用或切换账号
            // （避免 502 high load 等瞬态错误把所有账号锁死）
            if status.as_u16() == 408 || status.is_server_error() {
                let conc = self.concurrency_snapshot();
                tracing::warn!(
                    evt = "upstream_error",
                    status_code = status.as_u16(),
                    cred = ctx.id,
                    attempt = attempt + 1,
                    max_retries = max_retries,
                    conc_in_use = conc.in_use,
                    conc_wait = conc.waiting,
                    conc_max = conc.max,
                    "API 请求失败（上游瞬态错误）: {} {}",
                    status,
                    body
                );
                last_error = Some(anyhow::anyhow!(
                    "{} API 请求失败: {} {}",
                    api_type,
                    status,
                    body
                ));
                if attempt + 1 < max_retries {
                    sleep(Self::retry_delay(attempt)).await;
                }
                continue;
            }

            // 其他 4xx - 通常为请求/配置问题：直接返回，不计入账号失败
            if status.is_client_error() {
                anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
            }

            // 兜底：当作可重试的瞬态错误处理（不切换账号）
            tracing::warn!(
                "API 请求失败（未知错误，尝试 {}/{}）: {} {}",
                attempt + 1,
                max_retries,
                status,
                body
            );
            last_error = Some(anyhow::anyhow!(
                "{} API 请求失败: {} {}",
                api_type,
                status,
                body
            ));
            if attempt + 1 < max_retries {
                sleep(Self::retry_delay(attempt)).await;
            }
        }

        // 所有重试都失败
        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!(
                "{} API 请求失败：已达到最大重试次数（{}次）",
                api_type,
                max_retries
            )
        }))
    }

    fn retry_delay(attempt: usize) -> Duration {
        // 指数退避 + 少量抖动，避免上游抖动时放大故障
        const BASE_MS: u64 = 200;
        const MAX_MS: u64 = 5_000;
        let exp = BASE_MS.saturating_mul(2u64.saturating_pow(attempt.min(6) as u32));
        let backoff = exp.min(MAX_MS);
        let jitter_max = (backoff / 4).max(1);
        let jitter = fastrand::u64(0..=jitter_max);
        Duration::from_millis(backoff.saturating_add(jitter))
    }

    /// 429 限流专用退避：起步更高、上限更大。
    /// 单 Kiro 账号场景下，“切换账号”无账号可切，快速重试只会火上浇油。
    /// 用较长退避让上游限流窗口过去，减少瞬时 429 空转放大。
    fn throttle_delay(attempt: usize) -> Duration {
        // 800ms 起步，指数退避到最多 15s，加抖动防雪崩
        const BASE_MS: u64 = 800;
        const MAX_MS: u64 = 15_000;
        let exp = BASE_MS.saturating_mul(2u64.saturating_pow(attempt.min(6) as u32));
        let backoff = exp.min(MAX_MS);
        let jitter_max = (backoff / 3).max(1);
        let jitter = fastrand::u64(0..=jitter_max);
        Duration::from_millis(backoff.saturating_add(jitter))
    }

    fn is_monthly_request_limit(body: &str) -> bool {
        if body.contains("MONTHLY_REQUEST_COUNT") {
            return true;
        }

        let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
            return false;
        };

        if value
            .get("reason")
            .and_then(|v| v.as_str())
            .is_some_and(|v| v == "MONTHLY_REQUEST_COUNT")
        {
            return true;
        }

        value
            .pointer("/error/reason")
            .and_then(|v| v.as_str())
            .is_some_and(|v| v == "MONTHLY_REQUEST_COUNT")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kiro::token_manager::CallContext;
    use crate::model::config::Config;

    fn create_test_provider(config: Config, credentials: KiroCredentials) -> KiroProvider {
        let tm = MultiTokenManager::new(config, vec![credentials], None, None, false).unwrap();
        KiroProvider::new(Arc::new(tm))
    }

    /// 并发上限计算：绝对值逃生口 + 每账号×账号数。
    /// 集中在一个测试里顺序跑，避免并行测试污染全局 env。
    #[test]
    fn test_initial_concurrency_config() {
        // 清理环境，从默认值开始
        unsafe {
            std::env::remove_var("KIRO_MAX_CONCURRENT");
            std::env::remove_var("KIRO_CONCURRENT_PER_ACCOUNT");
        }
        // 默认：每账号 5 × 账号数，不锁定
        assert_eq!(initial_concurrency_config(1), (5, false, 5));
        assert_eq!(initial_concurrency_config(3), (15, false, 5));
        // 0 账号按 1 算，不为 0
        assert_eq!(initial_concurrency_config(0), (5, false, 5));

        // 每账号覆盖
        unsafe { std::env::set_var("KIRO_CONCURRENT_PER_ACCOUNT", "4"); }
        assert_eq!(initial_concurrency_config(1), (4, false, 4));
        assert_eq!(initial_concurrency_config(2), (8, false, 4));

        // 绝对值逃生口优先，锁定=true，忽略账号数
        unsafe { std::env::set_var("KIRO_MAX_CONCURRENT", "6"); }
        assert_eq!(initial_concurrency_config(10), (6, true, 4));
        assert_eq!(initial_concurrency_config(1), (6, true, 4));

        // 非法绝对值回退到 per-account×n，不锁定
        unsafe { std::env::set_var("KIRO_MAX_CONCURRENT", "0"); }
        assert_eq!(initial_concurrency_config(2), (8, false, 4)); // per=4, n=2
        unsafe { std::env::set_var("KIRO_MAX_CONCURRENT", "abc"); }
        assert_eq!(initial_concurrency_config(2), (8, false, 4));

        // 清理，避免影响其他测试
        unsafe {
            std::env::remove_var("KIRO_MAX_CONCURRENT");
            std::env::remove_var("KIRO_CONCURRENT_PER_ACCOUNT");
        }
    }

    /// 运行时 resize：扩容立即生效，缩容不负值，热改每账号值按账号数重算。
    #[test]
    fn test_concurrency_controller_resize() {
        // 初始：每账号 5，2 个账号 = 10，不锁定
        let ctrl = ConcurrencyController::new(10, 5, false);
        assert_eq!(ctrl.max(), 10);
        assert_eq!(ctrl.per_account(), 5);
        assert_eq!(ctrl.snapshot().available, 10);

        // 热加一个账号（3 个）→ 上限 15，扩容立即生效
        let (old, new) = ctrl.recompute_for_accounts(3);
        assert_eq!((old, new), (10, 15));
        assert_eq!(ctrl.max(), 15);
        assert_eq!(ctrl.snapshot().available, 15);

        // 热改每账号值为 8（3 个账号）→ 上限 24
        let (old, new) = ctrl.set_per_account(8, 3).expect("未锁定应成功");
        assert_eq!((old, new), (15, 24));
        assert_eq!(ctrl.max(), 24);
        assert_eq!(ctrl.per_account(), 8);

        // 缩容：账号减到 1 → 上限 8（全部空闲，可立即回收）
        let (old, new) = ctrl.recompute_for_accounts(1);
        assert_eq!((old, new), (24, 8));
        assert_eq!(ctrl.max(), 8);
        assert_eq!(ctrl.snapshot().available, 8);
    }

    /// 绝对值锁定时：recompute 为 no-op，set_per_account 返回 Err。
    #[test]
    fn test_concurrency_controller_absolute_lock() {
        let ctrl = ConcurrencyController::new(6, 5, true);
        assert_eq!(ctrl.max(), 6);
        // 账号数变化不影响上限
        assert_eq!(ctrl.recompute_for_accounts(100), (6, 6));
        assert_eq!(ctrl.max(), 6);
        // 热改每账号值被拒绝
        assert!(ctrl.set_per_account(20, 100).is_err());
        assert_eq!(ctrl.max(), 6);
    }

    /// 首字节超时读取：默认 32 / env 覆盖 / 0 禁用 / 非法回退。
    #[test]
    fn test_first_byte_timeout_secs() {
        unsafe { std::env::remove_var("KIRO_FIRST_BYTE_TIMEOUT_SECS"); }
        assert_eq!(first_byte_timeout_secs(), 32); // 默认

        unsafe { std::env::set_var("KIRO_FIRST_BYTE_TIMEOUT_SECS", "45"); }
        assert_eq!(first_byte_timeout_secs(), 45); // env 覆盖

        unsafe { std::env::set_var("KIRO_FIRST_BYTE_TIMEOUT_SECS", "0"); }
        assert_eq!(first_byte_timeout_secs(), 0); // 0 = 禁用首字节超时

        unsafe { std::env::set_var("KIRO_FIRST_BYTE_TIMEOUT_SECS", "abc"); }
        assert_eq!(first_byte_timeout_secs(), 32); // 非法回退默认

        unsafe { std::env::remove_var("KIRO_FIRST_BYTE_TIMEOUT_SECS"); }
    }

    #[test]
    fn test_base_url() {
        let config = Config::default();
        let credentials = KiroCredentials::default();
        let provider = create_test_provider(config, credentials);
        assert!(provider.base_url().contains("amazonaws.com"));
        assert!(provider.base_url().contains("generateAssistantResponse"));
    }

    #[test]
    fn test_base_domain() {
        let mut config = Config::default();
        config.region = "us-east-1".to_string();
        let credentials = KiroCredentials::default();
        let provider = create_test_provider(config, credentials);
        assert_eq!(provider.base_domain(), "q.us-east-1.amazonaws.com");
    }

    #[test]
    fn test_build_headers() {
        let mut config = Config::default();
        config.region = "us-east-1".to_string();
        config.kiro_version = "0.8.0".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.profile_arn = Some("arn:aws:sso::123456789:profile/test".to_string());
        credentials.refresh_token = Some("a".repeat(150));

        let provider = create_test_provider(config, credentials.clone());
        let ctx = CallContext {
            id: 1,
            credentials,
            token: "test_token".to_string(),
        };
        let headers = provider.build_headers(&ctx, "{}").unwrap();

        assert_eq!(headers.get(CONTENT_TYPE).unwrap(), "application/json");
        assert_eq!(headers.get("x-amzn-codewhisperer-optout").unwrap(), "true");
        assert_eq!(headers.get("x-amzn-kiro-agent-mode").unwrap(), "vibe");
        assert!(
            headers
                .get(AUTHORIZATION)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("Bearer ")
        );
        // Connection: close 已移除，启用 keep-alive 连接复用
        assert!(headers.get("connection").is_none());
    }

    #[test]
    fn test_is_monthly_request_limit_detects_reason() {
        let body = r#"{"message":"You have reached the limit.","reason":"MONTHLY_REQUEST_COUNT"}"#;
        assert!(KiroProvider::is_monthly_request_limit(body));
    }

    #[test]
    fn test_is_monthly_request_limit_nested_reason() {
        let body = r#"{"error":{"reason":"MONTHLY_REQUEST_COUNT"}}"#;
        assert!(KiroProvider::is_monthly_request_limit(body));
    }

    #[test]
    fn test_is_monthly_request_limit_false() {
        let body = r#"{"message":"nope","reason":"DAILY_REQUEST_COUNT"}"#;
        assert!(!KiroProvider::is_monthly_request_limit(body));
    }

    #[test]
    fn test_extract_agent_task_type_vibe_default() {
        assert_eq!(KiroProvider::extract_agent_task_type_from_request("{}"), "vibe");
        assert_eq!(KiroProvider::extract_agent_task_type_from_request("invalid json"), "vibe");
    }

    #[test]
    fn test_extract_agent_task_type_spectask() {
        let body = r#"{"conversationState":{"agentTaskType":"spectask","conversationId":"abc"}}"#;
        assert_eq!(KiroProvider::extract_agent_task_type_from_request(body), "spectask");
    }

    #[test]
    fn test_extract_agent_task_type_vibe_explicit() {
        let body = r#"{"conversationState":{"agentTaskType":"vibe","conversationId":"abc"}}"#;
        assert_eq!(KiroProvider::extract_agent_task_type_from_request(body), "vibe");
    }

    #[test]
    fn test_build_headers_spectask_mode() {
        let mut config = Config::default();
        config.region = "us-east-1".to_string();
        config.kiro_version = "0.8.0".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.profile_arn = Some("arn:aws:sso::123456789:profile/test".to_string());
        credentials.refresh_token = Some("a".repeat(150));

        let provider = create_test_provider(config, credentials.clone());
        let ctx = CallContext {
            id: 1,
            credentials,
            token: "test_token".to_string(),
        };
        let spectask_body = r#"{"conversationState":{"agentTaskType":"spectask"}}"#;
        let headers = provider.build_headers(&ctx, spectask_body).unwrap();
        assert_eq!(headers.get("x-amzn-kiro-agent-mode").unwrap(), "spectask");
    }
}
