import { createHash, randomUUID } from 'node:crypto'
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { rescheduleAfterRun } from './schedule.js'
import { findDshSkillMirror, invalidateDshSkills, syncSkillToDsh } from './dshskills.js'
import { skillPromptContent } from './skillpack.js'
import { buildShardWorkspaceInfo, planShards, planShardsAsync } from './sharding.js'
import { formatSignalsSection, scanRepositorySignals, scanRepositorySignalsAsync } from './scan.js'
import { formatScaSection, scanDependencies, scanDependenciesAsync } from './sca.js'
import { formatEvidenceProblems, normaliseRelativePath, verifyFindingEvidence } from './verify.js'
import { REVIEW_STATUSES, clip, nowIso } from './util.js'

/**
 * Host cancellation is best-effort: `agent.cancel()` may not always produce an
 * idle notification. These fallbacks keep a paused/cancelled run from staying
 * "running" forever.
 */
const SETTLE_TIMEOUT_MS = 8000
/** An idle that arrives before the first event of a turn means the turn never
 *  started (host still spinning up / followup not consumed). Keep re-arming
 *  the watcher for up to this long before declaring the session dead. Cold
 *  starts can legitimately take tens of seconds before the first event. */
const FIRST_EVENT_MAX_MS = 90_000
/** A running run with no session event for this long is flagged as stalled. */
const STALL_WARN_MS = 120_000
/** After this long without any event the run is considered dead and failed.
 *  Generous on purpose: a single long tool call (build/test) emits no events
 *  while it runs, and we must not kill a legitimately slow audit. */
const STALL_FAIL_MS = 1_800_000
/** Progress heartbeat so the UI can tell "thinking" apart from "stuck". */
const HEARTBEAT_MS = 3000
/** Hard cap for the wall-clock budget so a mistyped setting cannot disable it. */
const MAX_RUN_DURATION_CEILING_MS = 7 * 24 * 60 * 60 * 1000
/** Hard cap for the token budget so a mistyped setting cannot disable it. */
const MAX_TOKENS_CEILING = 1_000_000_000
/**
 * 默认单次运行的 token 预算（约 300 万）。0 表示不限，但历史上有用户在这个
 * 默认值上“一会就花了 10M”，因此默认给一个可收敛的上限；用户仍可在设置里
 * 改为 0（不限）或其它值。超出后优雅停止并保留进度与发现。
 */
const DEFAULT_MAX_TOKENS_PER_RUN = 3_000_000

/**
 * Tool names that can mutate the audited repository or run arbitrary code.
 * The audit is strictly read-only: these are denied at the tool layer (not just
 * in the system prompt) via `tools.restrict` / `tools.guard` on the agent's
 * scoped context. `read`/`read_image`/`glob`/`grep` stay available; the only
 * write path is the `code_audit_*` result tools.
 */
const READ_ONLY_DENIED_TOOLS = [
  'write',
  'edit',
  'str_replace_editor',
  'bash',
  'pwsh',
  'terminal_open',
  'terminal_send',
  'terminal_signal',
  'apply_patch',
  'notebook_edit',
]
/** Name pattern used as a defence-in-depth guard beside the explicit deny set. */
const READ_ONLY_DENY_PATTERN = /^(write|edit|str_replace|apply_patch|notebook_|bash|pwsh|shell|terminal|exec|run_command)/i
/** Reason returned to the model when it attempts a denied (side-effecting) tool. */
const READ_ONLY_DENY_REASON =
  '当前处于只读审计会话：禁止修改/创建/删除文件、禁止安装依赖、禁止构建/测试/运行代码、禁止 git 写操作。' +
  '只能用 read/read_image/glob/grep 查看代码，并通过 code_audit_* 工具上报结果。'

/** Parse the max-run-duration setting (minutes); 0/invalid means "no limit". */
export function MaxRunDurationMs(value) {
  const n = Number(value)
  if (!Number.isFinite(n) || n <= 0) return 0
  return Math.min(Math.floor(n), MAX_RUN_DURATION_CEILING_MS / 60_000) * 60_000
}

/** Parse the per-run token budget setting; 0/invalid means "unlimited". */
export function MaxTokensPerRun(value) {
  const n = Number(value)
  if (!Number.isFinite(n) || n <= 0) return 0
  return Math.min(Math.floor(n), MAX_TOKENS_CEILING)
}

const USAGE_KEYS = {
  input: ['input_tokens', 'prompt_tokens', 'inputTokens', 'promptTokens'],
  output: ['output_tokens', 'completion_tokens', 'outputTokens', 'completionTokens'],
  cost: ['costUSD', 'cost_usd', 'costUsd', 'totalCostUSD'],
}

/** First non-negative finite number among the given keys of an object. */
function firstUsageNumber(source, keys) {
  for (const key of keys) {
    const value = Number(source?.[key])
    if (Number.isFinite(value) && value >= 0) return value
  }
  return 0
}

/**
 * Best-effort token accounting. DSH session events may attach usage data in
 * several shapes depending on the provider; sum whatever we can find into
 * progress so the UI/report can show consumption and enforce a per-run
 * budget. Per-message usage objects are preferred (additive by design);
 * unknown shapes contribute nothing instead of breaking the run. The exact
 * event shape should be tightened once a real trajectory confirms it.
 */
function accumulateUsage(entry, event) {
  const data = event?.data
  if (!data || typeof data !== 'object') return
  const usage = [data.message?.usage, data.usage, data.tokens, data].find(
    candidate => candidate && typeof candidate === 'object',
  )
  if (!usage) return
  const tokensIn = firstUsageNumber(usage, USAGE_KEYS.input)
  const tokensOut = firstUsageNumber(usage, USAGE_KEYS.output)
  const cost = firstUsageNumber(usage, USAGE_KEYS.cost)
  if (!tokensIn && !tokensOut && !cost) return
  const progress = entry.progress
  progress.tokensIn = (progress.tokensIn ?? 0) + tokensIn
  progress.tokensOut = (progress.tokensOut ?? 0) + tokensOut
  if (cost) progress.estCostUsd = (progress.estCostUsd ?? 0) + cost
}

/**
 * Infer audit progress from session events instead of trusting the model's
 * own reports (issue #10). Two signals feed progress automatically:
 * - read files: every file a read-type tool opens is matched against the
 *   audited file list (slice list in shard mode, whole-repo plan in single
 *   mode) and merged into the durable files_read ledger;
 * - findings count: re-derived from the store on submit_finding calls.
 * The model's report_progress stays a hint (stage/note text), never the
 * source of truth for coverage numbers.
 */
const READ_TOOL_PATTERN = /\bread\b|read_file|readfile|open_file|view_file|cat\b|get_file/i
const FINDING_TOOL_PATTERN = /submit_finding/i

/** Pull a plausible file path out of a tool/call event payload. */
function eventFilePath(data) {
  const candidates = [
    data?.path,
    data?.file_path,
    data?.filePath,
    data?.filename,
    data?.args?.path,
    data?.args?.file_path,
    data?.args?.filePath,
    data?.input?.path,
    data?.input?.file_path,
  ]
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim()) return candidate.trim()
  }
  return null
}

/** Extract a local file path from a path that may carry a file:// prefix. */
function stripFileUrl(value) {
  if (/^file:\/\//i.test(value)) {
    try {
      return decodeURIComponent(new URL(value).pathname)
    } catch {
      return value.replace(/^file:\/\//i, '')
    }
  }
  return value
}

/**
 * Auto-derive coverage from read-type tool calls. Returns the relative path
 * when the file belongs to the audited list, otherwise null. Resolution is
 * defensive: agent tools may pass absolute paths (file:// included) or
 * Windows separators; only real members of the audit list count, so junk
 * paths can never inflate coverage.
 */
export function matchReadFile(entry, rawPath, store) {
  if (!rawPath || typeof rawPath !== 'string') return null
  const value = stripFileUrl(rawPath.trim())
  if (!value) return null
  // The audited list is resolved lazily and cached on the entry: shard entries
  // know their slice list, single entries fall back to the whole-repo plan.
  let audited = entry.auditedList
  if (!Array.isArray(audited)) {
    if (entry.kind === 'shard') {
      audited = entry.plan?.shards?.[entry.shardIndex]?.files
    } else if (entry.kind === 'single') {
      // Prefer the plan captured at start; only fall back to a fresh walk when
      // it is absent. The async-safe walk is used because matchReadFile runs
      // synchronously inside tool hooks and the sync walker would block here.
      audited = entry.plan?.shards?.[0]?.files
        ?? entry.task?.auditedListCache
        ?? planShardsSafe(entry.task?.repo_path)?.shards?.[0]?.files
        ?? null
    } else {
      return null // aggregate sessions reconcile, they do not read for coverage
    }
    if (Array.isArray(audited)) entry.auditedList = audited // cache for later calls
  }
  if (!Array.isArray(audited) || audited.length === 0) return null
  const auditedSet = audited.map(file => normaliseRelativePath(file))
  // Windows paths are case-insensitive and the agent may echo the drive letter
  // in any casing, so also index lowercased copies and fall back to that when
  // the exact-case lookup misses. On case-sensitive platforms this is a no-op
  // (paths already match exactly), so it only recovers real Windows matches.
  const auditedLower = new Map()
  for (const file of auditedSet) auditedLower.set(file.toLowerCase(), file)
  let relative = null
  try {
    const resolved = resolve(entry.task?.repo_path ?? '', value)
    const repoRoot = resolve(entry.task?.repo_path ?? '')
    if (resolved.toLowerCase().startsWith(repoRoot.toLowerCase() + (repoRoot.endsWith('\\') || repoRoot.endsWith('/') ? '' : '\\'))) {
      relative = resolved.slice(repoRoot.length).replace(/^[\\/]+/, '').replaceAll('\\', '/')
    } else if (!/^([a-zA-Z]:[\\/]|\/)/.test(value)) {
      relative = normaliseRelativePath(value)
    } else {
      return null
    }
  } catch {
    relative = normaliseRelativePath(value)
  }
  if (!relative) return null
  if (auditedSet.includes(relative)) return relative
  // Case-insensitive fallback for Windows drive-letter / path casing drift.
  return auditedLower.get(relative.toLowerCase()) ?? null
}

/** Drives audit runs by creating isolated DSH agent sessions. */
export class AuditRunner {
  constructor({ ctx, store, dataDir, config = {}, resolveDefaultModel }) {
    this.ctx = ctx
    this.store = store
    this.dataDir = dataDir
    this.config = config
    this.resolveDefaultModel = typeof resolveDefaultModel === 'function' ? resolveDefaultModel : () => null
    this.trajectoryDir = join(dataDir, 'trajectories')
    this.reportsDir = join(dataDir, 'reports')
    mkdirSync(this.trajectoryDir, { recursive: true })
    mkdirSync(this.reportsDir, { recursive: true })
    /** runId -> { handle, sessionId, assistantText, summary, cancelRequested, pauseRequested, progress, error } */
    this.active = new Map()
    /** Paused runs keep their live session so they can continue from the interruption point. */
    this.paused = new Map()
    /** Finished sessions kept alive so their conversation remains in the client sidebar. */
    this.retained = []
    this.maxRetained = Number(config.maxRetainedSessions) || 50
    /** sessionId -> runId */
    this.sessionRuns = new Map()
    // Paused runs only live in memory. Records left over from a previous
    // process can never be resumed, so close them instead of showing a stuck
    // "已暂停" state.
    for (const run of store.pausedRuns()) {
      store.updateRun(run.id, {
        status: 'cancelled',
        finished_at: nowIso(),
        error: '插件重启，暂停的会话已失效，请重新运行任务',
      })
      this.closeShardRecords(run.id, {
        runningStatus: 'cancelled',
        pendingStatus: 'cancelled',
        note: '插件重启，暂停的会话已失效，请重新运行任务',
      })
      const task = store.getTask(run.task_id)
      if (task && task.status === 'paused') store.updateTask(task.id, { status: 'cancelled' })
    }
  }

  /**
   * Enforce the read-only audit contract at the *tool layer* on one agent's
   * scoped context. The system prompt already forbids writes, but a prompt is
   * advisory — this masks write-capable tools in the registry so the model
   * cannot call them even if it tries.
   *
   * Must run from `setup(agentCtx)` after the agent preset is mounted, so
   * `agentCtx.get('tools')` resolves the per-agent tools service (whose scope
   * is this agent). `tools.restrict()` throws when the context is unscoped,
   * which is exactly the safety gate we rely on: if it throws we never fall
   * through to registering a guard, because a guard on an unscoped service
   * would leak globally and deny tools for every other agent.
   *
   * Best-effort and non-fatal: an enforcement failure must not abort the
   * audit, so every error is caught and logged; the prompt-layer prohibition
   * stays as the guaranteed baseline.
   */
  applyReadOnlyEnforcement(agentCtx) {
    if (this.store.getSetting('enforceReadOnlyTools', this.config.enforceReadOnlyTools ?? true) === false) return
    let tools
    try {
      tools = agentCtx?.get?.('tools') ?? agentCtx?.tools
    } catch {
      tools = undefined
    }
    if (!tools || typeof tools.restrict !== 'function') return
    // Only name tools this registry actually knows; restrict() rejects unknown
    // names, so intersect with the restrictable set when it is exposed.
    let restrictable
    try {
      restrictable = tools.view?.(agentCtx)?.restrictableNames
    } catch {
      restrictable = undefined
    }
    const deny = restrictable
      ? READ_ONLY_DENIED_TOOLS.filter(name => restrictable.has(name))
      : READ_ONLY_DENIED_TOOLS.slice()
    let restricted = false
    if (deny.length > 0) {
      try {
        tools.restrict({ deny })
        restricted = true
      } catch (error) {
        // Unscoped context or unknown names: skip enforcement silently rather
        // than risk a global mask. The prompt still forbids writes.
        return
      }
    }
    // Defence in depth: a name-pattern guard catches tools we did not enumerate
    // (and blocks even if a preset re-registers a write tool locally). Safe to
    // add only now that restrict proved this is the agent's own scope.
    if (restricted && typeof tools.guard === 'function') {
      try {
        tools.guard(exec => (exec && typeof exec.name === 'string' && READ_ONLY_DENY_PATTERN.test(exec.name)
          ? READ_ONLY_DENY_REASON
          : undefined))
      } catch {
        /* guard is a backstop; restrict already did the enforcing */
      }
    }
  }

  /** Live agent sessions visible to the developer; one at a time per run. */
  isRunning(taskId) {
    for (const entry of this.active.values()) {
      if (entry.taskId === taskId) return true
    }
    return false
  }

  /** The run of a task that is currently paused and can be continued. */
  pausedRun(taskId) {
    for (const [runId, entry] of this.paused) {
      if (entry.taskId === taskId) return { runId, entry }
    }
    return null
  }

  limit() {
    const configured = Number(this.store.getSetting('maxConcurrentRuns', this.config.maxConcurrentRuns ?? 1))
    return Number.isFinite(configured) && configured > 0 ? Math.floor(configured) : 1
  }

  /**
   * Return the live DSH mirror for a skill, re-creating it when missing. A user
   * may uninstall the mirrored skill from the DSH skill center, which would
   * otherwise force every audit to fall back to inlining the whole skill text.
   */
  ensureSkillMirror(skill) {
    const existing = findDshSkillMirror(skill)
    if (existing) return existing
    const result = syncSkillToDsh(skill)
    if (!result.synced) return null
    invalidateDshSkills(this.ctx)
    return findDshSkillMirror(skill) ?? { name: result.name, dir: result.dir }
  }

  /**
   * Wait for the agent to become idle, then either continue or finish.
   * The watcher is bound to the entry's epoch so a late notification from a
   * previous turn (pause/resume) can never end a freshly resumed run.
   */
  watchIdle(runId) {
    const entry = this.active.get(runId)
    if (!entry) return
    const epoch = entry.epoch
    const settle = error => {
      const current = this.active.get(runId)
      if (!current || current !== entry || current.epoch !== epoch) return
      if (error) current.error = String(error?.message ?? error)
      this.handleIdle(runId, epoch)
    }
    try {
      const idle = entry.handle.agent.whenIdle()
      if (idle && typeof idle.then === 'function') idle.then(() => settle(), error => settle(error))
      else settle()
    } catch (error) {
      settle(error)
    }
  }

  handleIdle(runId, epoch) {
    const entry = this.active.get(runId)
    if (!entry) return
    if (epoch !== undefined && entry.epoch !== epoch) return
    if (entry.pauseRequested) {
      this.finish(runId, { paused: true })
      return
    }
    if (entry.cancelRequested) {
      this.finish(runId, { cancelled: true })
      return
    }
    if (entry.error) {
      this.scheduleRetry(runId, entry.error)
      return
    }
    // `whenIdle()` can resolve while the agent is still idle from the previous
    // turn, i.e. before the followup we just sent starts anything. Finishing
    // here is what made "继续" look like it did nothing, so wait for real
    // activity and re-arm instead of completing the run.
    const followupAt = entry.followupAt ?? 0
    const sawEvent = (entry.eventAt ?? 0) >= followupAt
    if (!sawEvent) {
      if (Date.now() - followupAt < FIRST_EVENT_MAX_MS) {
        const timer = setTimeout(() => this.watchIdle(runId), 1000)
        timer.unref?.()
        return
      }
      this.finish(runId, { error: 'Agent 没有响应指令，审计会话可能已失效，请重新运行任务' })
      return
    }
    // Sharded audits fan out into worker sessions (one per slice) plus a final
    // aggregation session; each kind advances the run differently.
    if (entry.kind === 'shard') {
      void this.onShardIdle(runId)
      return
    }
    // Issue #4: the review pass closes the whole run; aggregate/single hands
    // over to it (maybeStartReview decides review vs. finish).
    if (entry.kind === 'review') {
      this.finish(runId)
      return
    }
    if (entry.kind === 'aggregate') {
      this.maybeStartReview(runId)
      return
    }
    this.maybeStartReview(runId)
  }

  /** Periodic liveness ping so the console can distinguish thinking from stuck. */
  startHeartbeat(runId) {
    const entry = this.active.get(runId)
    if (!entry || entry.heartbeatTimer) return
    entry.heartbeatTimer = setInterval(() => this.heartbeat(runId), HEARTBEAT_MS)
    entry.heartbeatTimer.unref?.()
  }

  heartbeat(runId) {
    const entry = this.active.get(runId)
    if (!entry) return
    const since = Date.now() - (entry.eventAt || entry.followupAt || Date.now())
    const progress = entry.progress
    progress.heartbeatAt = nowIso()
    progress.lastEventAt = entry.eventAt ? new Date(entry.eventAt).toISOString() : progress.lastEventAt ?? null
    progress.idleSeconds = Math.max(0, Math.round(since / 1000))
    progress.stalled = since >= STALL_WARN_MS
    // Honour a pending pause/cancel before any failure path below.
    if (entry.pauseRequested) {
      this.finish(runId, { paused: true })
      return
    }
    if (entry.cancelRequested) {
      this.finish(runId, { cancelled: true })
      return
    }
    // Hard wall-clock budget: a run that exceeds its configured duration is
    // stopped even if it is still emitting events (stall detection only
    // covers the "no activity" case).
    const maxDurationMs = MaxRunDurationMs(this.store.getSetting('maxRunDurationMinutes', this.config.maxRunDurationMinutes ?? 0))
    if (maxDurationMs > 0 && entry.startedAt > 0 && Date.now() - entry.startedAt >= maxDurationMs) {
      this.finish(runId, {
        error: `审计超过最大允许时长 ${Math.round(maxDurationMs / 60_000)} 分钟，已按预算停止（进度与发现已保留，可从暂停记录继续或重跑）`,
      })
      return
    }
    if (since >= STALL_FAIL_MS) {
      this.finish(runId, {
        error: `审计已 ${Math.round(since / 60000)} 分钟没有任何新活动，已判定为卡住并终止`,
      })
      return
    }
    this.persistProgress(runId)
  }

  clearRunTimers(entry) {
    if (!entry) return
    if (entry.retryTimer) clearTimeout(entry.retryTimer)
    if (entry.progressTimer) clearTimeout(entry.progressTimer)
    if (entry.settleTimer) clearTimeout(entry.settleTimer)
    if (entry.heartbeatTimer) clearInterval(entry.heartbeatTimer)
    entry.retryTimer = null
    entry.progressTimer = null
    entry.settleTimer = null
    entry.heartbeatTimer = null
  }

  /**
   * A model reply failed (timeout, network error, 5xx...). Keep the run alive
   * and send a "continue" message after the configured delay, up to the
   * configured number of recoveries; only then mark the run as failed.
   */
  scheduleRetry(runId, error) {
    const entry = this.active.get(runId)
    if (!entry) return
    // Both the idle watcher and a rejected followup can land here for the same
    // failure; a second timer would double-continue the session.
    if (entry.retryTimer) return
    const limit = RetryCount(this.store.getSetting('llmRetryCount', this.config.llmRetryCount ?? 3))
    if (entry.retries >= limit) {
      this.finish(runId, { error })
      return
    }
    const delay = RetryMinutes(
      this.store.getSetting('llmRetryDelayMinutes', this.config.llmRetryDelayMinutes ?? 5),
    )
    const next = entry.retries + 1
    entry.error = null
    entry.progress.stage = '等待续跑'
    entry.progress.note = `${delay > 0 ? `${delay} 分钟后` : '立即'}自动续跑（第 ${next}/${limit} 次）：${clip(error, 160)}`
    entry.progress.percent = Math.max(entry.progress.percent ?? 0, 10)
    this.persistProgress(runId)
    entry.retryTimer = setTimeout(() => {
      const current = this.active.get(runId)
      if (!current) return
      current.retryTimer = null
      if (current.pauseRequested || current.cancelRequested) {
        this.finish(runId, current.pauseRequested ? { paused: true } : { cancelled: true })
        return
      }
      current.retries = next
      current.error = null
      current.epoch = (current.epoch ?? 0) + 1
      current.idleArms = 0
      current.eventAt = 0
      current.startedAt = Date.now()
      current.followupAt = Date.now()
      current.progress.stage = '继续审计'
      current.progress.note = `自动续跑第 ${next}/${limit} 次（上次失败：${clip(error, 120)}）`
      this.persistProgress(runId)
      this.startHeartbeat(runId)
      try {
        const queued = current.handle.agent.followup(current.createUserMessage({
          content: [{
            type: 'text',
            text: '继续。上一次模型回复失败或中断，请从中断处继续完成审计任务，不要重复已经完成的工作。',
          }],
          source: { kind: 'user' },
        }))
        if (queued && typeof queued.then === 'function') {
          queued.catch(retryError => {
            const pending = this.active.get(runId)
            if (!pending) return
            pending.error = String(retryError?.message ?? retryError)
            this.scheduleRetry(runId, pending.error)
          })
        }
      } catch (retryError) {
        current.error = String(retryError?.message ?? retryError)
        this.scheduleRetry(runId, current.error)
        return
      }
      this.watchIdle(runId)
    }, delay * 60_000)
    entry.retryTimer.unref?.()
  }

  /**
   * Resolve provider/model for a run: the task selection wins, then the plugin
   * default, then the DSH default model used by normal client sessions.
   */
  resolveSelection(task) {
    let preset = {}
    try {
      preset = this.resolveDefaultModel() ?? {}
    } catch {
      preset = {}
    }
    const configuredProvider = String(
      task.provider || this.store.getSetting('defaultProvider', this.config.defaultProvider ?? '') || '',
    ).trim()
    const configuredModel = String(
      task.model || this.store.getSetting('defaultModel', this.config.defaultModel ?? '') || '',
    ).trim()
    const provider = configuredProvider || String(preset.provider ?? '').trim()
    let model = configuredModel
    // Only borrow the host default model when it belongs to the same provider.
    if (!model && (!configuredProvider || String(preset.provider ?? '') === configuredProvider)) {
      model = String(preset.model ?? '').trim()
    }
    return { provider, model, reasoningEffort: preset.reasoningEffort }
  }

  /** Start a run for a task. Returns the run record. */
  async start(taskId, trigger = 'manual') {
    const task = this.store.getTask(taskId)
    if (!task) throw new Error('审计任务不存在')
    if (!task.repo_path) throw new Error('审计任务缺少代码目录')
    if (this.isRunning(taskId)) throw new Error('该任务已有正在运行的审计')
    if (this.active.size >= this.limit()) throw new Error('已达到最大并发审计数，请稍后再试')
    // Starting again after a pause begins a brand new conversation.
    this.discardPaused(taskId)

    const auditMode = task.audit_mode === 'skill' ? 'skill' : 'prompts'
    const skill = auditMode === 'skill'
      ? (task.skill_id ? this.store.getSkill(task.skill_id) : undefined)
      : undefined
    const selectedPrompts = auditMode === 'skill'
      ? []
      : task.prompt_ids.map(id => this.store.getPrompt(id)).filter(prompt => prompt && prompt.enabled)
    if (auditMode === 'skill') {
      if (!skill) throw new Error('任务选择的审计 Skill 不存在，请编辑任务重新选择')
      if (!skill.enabled) throw new Error(`审计 Skill 已禁用：${skill.name}`)
    } else if (selectedPrompts.length === 0) {
      throw new Error('请先为任务选择至少一条启用的漏洞审计提示词')
    }
    // Prompt-mode audits shard the repository first: every slice gets its own
    // agent session plus a persisted read-file ledger, then a final session
    // aggregates cross-slice taint flows. Small repos fall back to the
    // single-session path.
    // Plan shards off the event loop: walking a large repository synchronously
    // here used to freeze the DSH host's web server and every concurrent
    // session for the duration of the scan.
    const plan = auditMode === 'prompts' ? await planShardsSafeAsync(task.repo_path) : null
    const sharded = !!plan && plan.mode === 'sharded'
    const auditUnits = sharded ? plan.shards.length : auditMode === 'skill' ? 1 : selectedPrompts.length
    const unitNames = auditMode === 'skill' ? [skill.name] : selectedPrompts.map(prompt => prompt.name)

    const selection = this.resolveSelection(task)
    if (!selection.provider || !selection.model) {
      throw new Error('未选择模型：请在 DSH 设置中配置默认模型，或编辑任务选择模型后重试')
    }

    const run = this.store.createRun(taskId, trigger)
    const sessionId = randomUUID()
    const trajectoryPath = join(this.trajectoryDir, `${run.id}.jsonl`)
    writeFileSync(
      trajectoryPath,
      `${JSON.stringify({
        type: 'audit/run-start',
        time: nowIso(),
        data: { runId: run.id, taskId, taskName: task.name, repoPath: task.repo_path, trigger, shardPlan: plan?.strategy ?? null },
      })}\n`,
    )
    this.store.updateRun(run.id, { session_id: sessionId, trajectory_path: trajectoryPath })
    this.store.updateTask(taskId, { status: 'running', last_run_at: nowIso() })

    // 让本次审计产生的会话出现在侧栏对应的工作区里，而不是“未分组”。
    // DSH 的会话按 cwd 归入工作区：只有存在一个 path 等于会话 cwd 的工作区，
    // 会话才会被收纳。这里在启动前确保该代码目录已注册为工作区（幂等，
    // 已存在则复用）。失败不影响审计本身。
    await this.ensureWorkspace(task.repo_path)

    // Sharded mode persists every slice up front so coverage survives restarts.
    let shardRecords = []
    if (sharded) {
      for (const shard of plan.shards) {
        shardRecords.push(this.store.createShard(run.id, taskId, shard))
      }
    }

    // SCA pre-pass (problem #2 gap): parse dependency manifests and record any
    // known-vulnerable components as pre-confirmed findings. Runs once at start
    // (manifests are typically root-level, so recording once avoids per-shard
    // duplication). Degrades to no-op on any parse error — never blocks a run.
    const scaScan = auditMode === 'prompts' ? await scanDependenciesAsync(task.repo_path) : { vulns: [], manifests: [], depCount: 0 }
    if (scaScan.vulns.length) {
      try {
        this.recordDependencyFindings(run.id, taskId, scaScan.vulns)
      } catch {
        // ignore — dependency findings are an enhancement, not a hard requirement
      }
    }

    let handle
    try {
      const llm = await import('@deepseek-ai/dsh-llm')
      const createUserMessage = llm.createUserMessage
      if (typeof createUserMessage !== 'function') throw new Error('当前 DSH 版本缺少 createUserMessage')
      const agents = this.ctx.get('agents') ?? this.ctx.agents
      if (!agents) throw new Error('当前 DSH 运行环境未启用 Agent 服务')

      const presets = this.ctx.get?.('agentPresets')
      const agentOptions = {
        provider: selection.provider,
        model: selection.model,
      }
      if (selection.reasoningEffort) agentOptions.reasoningEffort = selection.reasoningEffort

      const sessionEnv = { createUserMessage, agents, presets, agentOptions, scaScan }
      if (sharded) {
        // Each slice runs in its own fresh session with its own read-file
        // ledger; the runner advances to the next slice when the session goes
        // idle, and a final aggregation session stitches cross-slice flows.
        await this.launchShard(run.id, task, plan, 0, sessionEnv)
      } else {
        handle = await agents.create({
          sessionId,
          meta: { cwd: task.repo_path, ...(presets ? { agentPreset: presets.defaultId } : {}) },
          agentOptions: Object.keys(agentOptions).length ? agentOptions : undefined,
          setup: async agentCtx => {
            if (presets) await presets.mount(agentCtx)
            this.applyReadOnlyEnforcement(agentCtx)
          },
        })
        this.active.set(run.id, {
          handle,
          taskId,
          sessionId,
          kind: 'single',
          assistantText: '',
          summary: '',
          cancelRequested: false,
          pauseRequested: false,
          retryTimer: null,
          progressTimer: null,
          settleTimer: null,
          heartbeatTimer: null,
          epoch: 0,
          idleArms: 0,
          eventAt: 0,
          followupAt: 0,
          startedAt: Date.now(),
          retries: 0,
          createUserMessage,
          error: null,
          promptNames: unitNames,
          donePrompts: [],
          readFiles: new Set(),
          auditMode,
          progress: {
            percent: 5,
            stage: '初始化',
            note: '已创建审计会话，等待 Agent 开始',
            prompt: '',
            done: 0,
            total: auditUnits,
            steps: 0,
            toolCalls: 0,
            findings: 0,
            updatedAt: nowIso(),
            heartbeatAt: nowIso(),
            lastEventAt: null,
            idleSeconds: 0,
            stalled: false,
          },
        })
        this.sessionRuns.set(sessionId, run.id)
        this.persistProgress(run.id)

        // Skill mode prefers a native `/skill-name` invocation. Re-mirror first
        // when the mirror is missing (e.g. uninstalled via the DSH skill center),
        // otherwise the prompt has to carry the whole skill text inline.
        const skillMirror = auditMode === 'skill' ? this.ensureSkillMirror(skill) : null
        // Static-analysis leads for the single-session path: scan the whole
        // audited file list. Degradation mirrors the shard path — scan errors
        // cost the prompt its lead section, never the audit itself.
        let repoSignals = null
        if (auditMode !== 'skill') {
          try {
            const fileList = plan?.shards?.[0]?.files ?? (await planShardsSafeAsync(task.repo_path))?.shards?.[0]?.files ?? []
            repoSignals = (await scanRepositorySignalsAsync(task.repo_path, fileList)).signals
          } catch {
            repoSignals = null
          }
        }
        const message = createUserMessage({
          content: [{
            type: 'text',
            text: auditMode === 'skill' ? buildSkillAuditPrompt(task, skill, skillMirror) : buildAuditPrompt(task, selectedPrompts, repoSignals, scaScan),
          }],
          source: { kind: 'user' },
        })
        const entryRef = this.active.get(run.id)
        if (entryRef) {
          entryRef.followupAt = Date.now()
          this.startHeartbeat(run.id)
        }
        const queued = handle.agent.followup(message)
        if (queued && typeof queued.then === 'function') {
          queued.catch(followupError => {
            const pending = this.active.get(run.id)
            if (!pending) return
            pending.error = String(followupError?.message ?? followupError)
            this.scheduleRetry(run.id, pending.error)
          })
        }
        if (entryRef) this.watchIdle(run.id)
      }
    } catch (error) {
      // Drop any half-initialized entry so later runs are not blocked.
      const partial = this.active.get(run.id)
      if (partial) {
        this.clearRunTimers(partial)
        this.active.delete(run.id)
        this.sessionRuns.delete(partial.sessionId ?? sessionId)
      }
      for (const candidate of [partial?.handle, handle]) {
        if (!candidate) continue
        try {
          await candidate.dispose()
        } catch {
          // ignore
        }
      }
      // A slice run that dies while starting must not leave slices "running".
      if (shardRecords.length > 0) {
        this.closeShardRecords(run.id, {
          runningStatus: 'failed',
          pendingStatus: 'cancelled',
          note: String(error?.message ?? error),
        })
      }
      this.store.updateRun(run.id, {
        status: 'failed',
        finished_at: nowIso(),
        error: String(error?.message ?? error),
        progress: {
          percent: 0,
          stage: '失败',
          note: clip(error?.message ?? error, 300),
          done: 0,
          total: auditUnits,
          steps: 0,
          toolCalls: 0,
          findings: 0,
          updatedAt: nowIso(),
        },
      })
      this.store.updateTask(taskId, { status: 'failed' })
      throw error
    }

    return this.store.getRun(run.id)
  }

  // ------------------------------------------------------------ shard mode

  /**
   * Mark the shards of a run that never finished. Used when the run dies, is
   * cancelled or the plugin unloads, so the coverage ledger never keeps a slice
   * stuck on "running" forever.
   */
  closeShardRecords(runId, { runningStatus = 'failed', pendingStatus = 'cancelled', note = '' } = {}) {
    for (const shard of this.store.listShards(runId)) {
      if (shard.status === 'completed' || shard.status === 'failed' || shard.status === 'cancelled') continue
      const status = shard.status === 'running' ? runningStatus : pendingStatus
      this.store.updateShard(shard.id, {
        status,
        error: note ? clip(note, 500) : null,
        finished_at: nowIso(),
      })
    }
  }

  /** Snapshot every shard as a compact array for progress reporting. */
  shardProgress(runId) {
    return this.store.listShards(runId).map(shard => ({
      id: shard.id,
      name: shard.name,
      path: shard.path,
      status: shard.status,
      fileCount: shard.file_count,
      readCount: shard.files_read.length,
      index: shard.index,
    }))
  }

  /**
   * Launch one slice of a sharded audit: its own agent session, its own working
   * memory (the slice file list) and its own read-file ledger.
   */
  async launchShard(runId, task, plan, shardIndex, sessionEnv, { doneOverride } = {}) {
    const shards = this.store.listShards(runId)
    const record = shards.find(shard => shard.index === shardIndex) ?? shards[shardIndex]
    if (!record) throw new Error(`切片 ${shardIndex + 1} 不存在，无法启动审计`)

    const prompts = (task.prompt_ids ?? [])
      .map(id => this.store.getPrompt(id))
      .filter(prompt => prompt && prompt.enabled !== false)

    const { createUserMessage, agents, presets, agentOptions } = sessionEnv
    const sessionId = randomUUID()
    const handle = await agents.create({
      sessionId,
      meta: {
        cwd: task.repo_path,
        ...(presets ? { agentPreset: presets.defaultId } : {}),
      },
      agentOptions: Object.keys(agentOptions).length ? agentOptions : undefined,
      setup: async agentCtx => {
        if (presets) await presets.mount(agentCtx)
        this.applyReadOnlyEnforcement(agentCtx)
      },
    })

    const doneCount = doneOverride ?? shards.filter(shard => shard.status === 'completed').length
    const entry = {
      handle,
      taskId: task.id,
      sessionId,
      kind: 'shard',
      shardId: record.id,
      shardIndex,
      plan,
      sessionEnv,
      task,
      assistantText: '',
      summary: '',
      cancelRequested: false,
      pauseRequested: false,
      retryTimer: null,
      progressTimer: null,
      settleTimer: null,
      heartbeatTimer: null,
      epoch: 0,
      idleArms: 0,
      eventAt: 0,
      followupAt: 0,
      startedAt: Date.now(),
      retries: 0,
      createUserMessage,
      error: null,
      promptNames: prompts.map(prompt => prompt.name),
      donePrompts: [],
      readFiles: new Set(),
      auditMode: 'prompts',
      progress: {
        percent: Math.max(5, Math.round(5 + (doneCount / Math.max(shards.length, 1)) * 85)),
        stage: '切片审计',
        note: `开始审计切片 ${shardIndex + 1}/${shards.length}：${record.name}`,
        prompt: record.name,
        done: doneCount,
        total: shards.length,
        steps: 0,
        toolCalls: 0,
        findings: this.store.countFindingsForRun(runId),
        updatedAt: nowIso(),
        heartbeatAt: nowIso(),
        lastEventAt: null,
        idleSeconds: 0,
        stalled: false,
        shards: this.shardProgress(runId),
      },
    }

    this.active.set(runId, entry)
    this.sessionRuns.set(sessionId, runId)
    this.store.updateShard(record.id, { status: 'running', session_id: sessionId, started_at: nowIso() })
    entry.progress.shards = this.shardProgress(runId)
    this.persistProgress(runId)

    const workspace = buildShardWorkspaceInfo(plan, plan.shards[shardIndex] ?? {
      index: shardIndex,
      name: record.name,
      path: record.path,
      fileCount: record.file_count,
      files: record.files,
    })
    // Static-analysis leads (problem #2): scan just this shard's files so the
    // prompt opens with concrete suspicious locations. A scan failure must
    // never block the audit — degrade to no signals.
    let shardSignals = null
    try {
      shardSignals = (await scanRepositorySignalsAsync(task.repo_path, record.files ?? [])).signals
    } catch {
      shardSignals = null
    }
    // SCA leads belong only to the shard that actually holds a dependency
    // manifest (usually the root shard); injecting them elsewhere just repeats
    // the same table across sessions.
    const SCA_MANIFESTS = ['package-lock.json', 'package.json', 'pom.xml', 'go.mod', 'requirements.txt']
    const shardHasManifest = (record.files ?? []).some(f => SCA_MANIFESTS.includes(String(f).replaceAll('\\', '/').split('/').pop()))
    const shardSca = shardHasManifest ? (sessionEnv?.scaScan ?? null) : null
    const message = createUserMessage({
      content: [{
        type: 'text',
        text: buildShardAuditPrompt(task, record, workspace, prompts, shardSignals, shardSca),
      }],
      source: { kind: 'user' },
    })

    entry.followupAt = Date.now()
    this.startHeartbeat(runId)
    const queued = handle.agent.followup(message)
    if (queued && typeof queued.then === 'function') {
      queued.catch(followupError => {
        const pending = this.active.get(runId)
        if (!pending) return
        pending.error = String(followupError?.message ?? followupError)
        this.scheduleRetry(runId, pending.error)
      })
    }
    this.watchIdle(runId)
    return entry
  }

  /**
   * The current slice went idle: persist its result, then move on to the next
   * slice or, once every slice is done, to the cross-slice aggregation session.
   */
  async onShardIdle(runId) {
    const entry = this.active.get(runId)
    if (!entry || entry.kind !== 'shard') return
    const shard = this.store.getShard(entry.shardId)
    if (!shard) {
      this.finish(runId, { error: '切片记录已丢失，无法继续审计' })
      return
    }

    if (entry.error) {
      this.scheduleRetry(runId, entry.error)
      return
    }

    const summary = clip(entry.summary || entry.assistantText, 4000)
    this.store.updateShard(shard.id, {
      status: 'completed',
      summary,
      finished_at: nowIso(),
      error: null,
    })
    // Issue #10: persist whatever the slice session auto-inferred before the
    // entry is torn down, so the durable ledger never loses late reads.
    if (entry.readFiles instanceof Set && entry.readFiles.size > 0) {
      try {
        const merged = [...new Set([...shard.files_read, ...entry.readFiles])]
        this.store.updateShard(shard.id, { files_read: merged })
      } catch {
        // ignore
      }
    }
    const run = this.store.getRun(runId)
    if (run?.trajectory_path) {
      try {
        appendFileSync(
          run.trajectory_path,
          `${JSON.stringify({
            sessionId: entry.sessionId,
            time: nowIso(),
            type: 'audit/shard-end',
            data: { shard: shard.name, index: shard.index, summary: clip(summary, 1500) },
          })}\n`,
        )
      } catch {
        // ignore
      }
    }

    this.clearRunTimers(entry)
    this.active.delete(runId)
    this.sessionRuns.delete(entry.sessionId)
    this.retainSession(entry, entry.task, run)

    const nextIndex = entry.shardIndex + 1
    const remaining = this.store.listShards(runId)
    const completedCount = remaining.filter(shard => shard.status === 'completed').length
    if (nextIndex < remaining.length) {
      try {
        await this.launchShard(runId, entry.task, entry.plan, nextIndex, entry.sessionEnv, {
          doneOverride: completedCount,
        })
      } catch (error) {
        this.finish(runId, { error: String(error?.message ?? error) })
      }
      return
    }

    try {
      await this.startAggregation(runId, entry.task, entry.plan, entry.sessionEnv)
    } catch (error) {
      this.finish(runId, { error: String(error?.message ?? error) })
    }
  }

  /**
   * All slices are audited. Run one last session that only reconciles what the
   * slice sessions could not see: cross-slice taint flows and shared guards.
   */
  async startAggregation(runId, task, plan, sessionEnv) {
    const run = this.store.getRun(runId)
    if (!run) return
    const shards = this.store.listShards(runId)
    const findings = this.store.listFindings({ taskId: run.task_id, runId })

    const { createUserMessage, agents, presets, agentOptions } = sessionEnv
    const sessionId = randomUUID()
    const handle = await agents.create({
      sessionId,
      meta: {
        cwd: task.repo_path,
        ...(presets ? { agentPreset: presets.defaultId } : {}),
      },
      agentOptions: Object.keys(agentOptions).length ? agentOptions : undefined,
      setup: async agentCtx => {
        if (presets) await presets.mount(agentCtx)
        this.applyReadOnlyEnforcement(agentCtx)
      },
    })

    const entry = {
      handle,
      taskId: task.id,
      sessionId,
      kind: 'aggregate',
      plan,
      sessionEnv,
      task,
      assistantText: '',
      summary: '',
      cancelRequested: false,
      pauseRequested: false,
      retryTimer: null,
      progressTimer: null,
      settleTimer: null,
      heartbeatTimer: null,
      epoch: 0,
      idleArms: 0,
      eventAt: 0,
      followupAt: 0,
      startedAt: Date.now(),
      retries: 0,
      createUserMessage,
      error: null,
      promptNames: [],
      donePrompts: [],
      readFiles: new Set(),
      auditMode: 'prompts',
      progress: {
        percent: 95,
        stage: '跨切片汇聚',
        note: '全部切片已完成，正在核对跨切片污点流',
        prompt: '',
        done: shards.length,
        total: shards.length,
        steps: 0,
        toolCalls: 0,
        findings: this.store.countFindingsForRun(runId),
        updatedAt: nowIso(),
        heartbeatAt: nowIso(),
        lastEventAt: null,
        idleSeconds: 0,
        stalled: false,
        shards: this.shardProgress(runId),
      },
    }

    this.active.set(runId, entry)
    this.sessionRuns.set(sessionId, runId)
    this.persistProgress(runId)

    const message = createUserMessage({
      content: [{ type: 'text', text: buildAggregatePrompt(task, plan, shards, findings) }],
      source: { kind: 'user' },
    })

    entry.followupAt = Date.now()
    this.startHeartbeat(runId)
    const queued = handle.agent.followup(message)
    if (queued && typeof queued.then === 'function') {
      queued.catch(followupError => {
        const pending = this.active.get(runId)
        if (!pending) return
        pending.error = String(followupError?.message ?? followupError)
        this.scheduleRetry(runId, pending.error)
      })
    }
    this.watchIdle(runId)
    return entry
  }

  /**
   * Issue #4: after the audit proper completes (aggregate or single), hand the
   * run over to an independent review pass that verifies each finding from a
   * fresh session before anything reaches the final report.
   */
  async maybeStartReview(runId) {
    const sourceEntry = this.active.get(runId)
    if (!sourceEntry) {
      this.finish(runId)
      return
    }
    const enabled = this.store.getSetting('findingReviewEnabled', this.config?.findingReviewEnabled ?? true)
    const run = this.store.getRun(runId)
    // Deterministic findings (dependency/SCA matches, pre-marked 'confirmed') do
    // not need an LLM reverse-check; exclude them so the review session only
    // spends passes on source-derived findings that can actually be wrong.
    const findings = run
      ? this.store.listFindings({ taskId: run.task_id, runId }).filter(f => f.review_status !== 'confirmed')
      : []
    if (!enabled || findings.length === 0) {
      this.finish(runId)
      return
    }
    try {
      await this.startReview(runId, sourceEntry, findings)
    } catch (reviewError) {
      // A failed review handover must not lose the audit result: finish with
      // the audit outcome and surface the review failure as a note.
      this.finish(runId, { error: `复核阶段启动失败：${String(reviewError?.message ?? reviewError)}` })
    }
  }

  async startReview(runId, sourceEntry, findings) {
    const { createUserMessage, agents, presets, agentOptions } = sourceEntry.sessionEnv
    const sessionId = randomUUID()
    const handle = await agents.create({
      sessionId,
      meta: {
        cwd: sourceEntry.task.repo_path,
        ...(presets ? { agentPreset: presets.defaultId } : {}),
      },
      agentOptions: Object.keys(agentOptions).length ? agentOptions : undefined,
      setup: async agentCtx => {
        if (presets) await presets.mount(agentCtx)
        this.applyReadOnlyEnforcement(agentCtx)
      },
    })

    const entry = {
      handle,
      taskId: sourceEntry.task.id,
      sessionId,
      kind: 'review',
      plan: sourceEntry.plan ?? null,
      sessionEnv: sourceEntry.sessionEnv,
      task: sourceEntry.task,
      assistantText: '',
      summary: '',
      cancelRequested: false,
      pauseRequested: false,
      retryTimer: null,
      progressTimer: null,
      settleTimer: null,
      heartbeatTimer: null,
      epoch: 0,
      idleArms: 0,
      eventAt: 0,
      followupAt: 0,
      startedAt: Date.now(),
      retries: 0,
      createUserMessage,
      error: null,
      promptNames: [],
      donePrompts: [],
      readFiles: sourceEntry.readFiles instanceof Set ? sourceEntry.readFiles : new Set(),
      auditMode: sourceEntry.auditMode ?? 'prompts',
      progress: {
        percent: Math.max(sourceEntry.progress?.percent ?? 90, 90),
        stage: '二次复核',
        note: `正在对 ${findings.length} 条发现做独立复核`,
        prompt: '',
        done: 0,
        total: findings.length,
        steps: 0,
        toolCalls: 0,
        findings: this.store.countFindingsForRun(runId),
        updatedAt: nowIso(),
        heartbeatAt: nowIso(),
        lastEventAt: null,
        idleSeconds: 0,
        stalled: false,
      },
    }

    this.active.set(runId, entry)
    this.sessionRuns.set(sessionId, runId)
    this.persistProgress(runId)

    const message = createUserMessage({
      content: [{ type: 'text', text: buildReviewPrompt(sourceEntry.task, findings) }],
      source: { kind: 'user' },
    })

    entry.followupAt = Date.now()
    this.startHeartbeat(runId)
    const queued = handle.agent.followup(message)
    if (queued && typeof queued.then === 'function') {
      queued.catch(followupError => {
        const pending = this.active.get(runId)
        if (!pending) return
        pending.error = String(followupError?.message ?? followupError)
        this.scheduleRetry(runId, pending.error)
      })
    }
    this.watchIdle(runId)
    return entry
  }

  /**
   * Record the files a slice session has finished reading. This is the durable
   * coverage ledger: without it a run cannot say which files were audited.
   */
  reportFiles(context, input) {
    const entry = this.active.get(context?.runId)
    if (!entry || entry.kind !== 'shard') {
      throw new Error('只有切片审计会话需要上报已读文件清单')
    }
    const shard = this.store.getShard(entry.shardId)
    if (!shard) throw new Error('切片记录已丢失，无法记录已读文件')

    const raw = Array.isArray(input?.files)
      ? input.files
      : String(input?.files ?? '').split(/[\n,;，；]/)
    // Issue #10: reconcile the model's report with the auto-inferred ledger.
    // Paths are normalised the same way as matchReadFile; anything outside
    // this slice's audit list is rejected instead of silently inflating
    // coverage (the model can only read-list what it actually read).
    const sliceFiles = new Set(
      (entry.plan?.shards?.[entry.shardIndex]?.files ?? []).map(file => normaliseRelativePath(file)),
    )
    const rejected = []
    const reported = []
    for (const item of raw) {
      const value = normaliseRelativePath(stripFileUrl(String(item ?? '')))
      if (!value) continue
      if (sliceFiles.size && !sliceFiles.has(value)) {
        rejected.push(value)
        continue
      }
      if (!reported.includes(value)) reported.push(value)
    }
    if (reported.length === 0 && rejected.length === 0) throw new Error('请提供至少一个已读文件路径')

    const merged = [...new Set([...shard.files_read, ...reported])]
    for (const path of reported) entry.readFiles.add(path)
    entry.progress.readFiles = entry.readFiles.size
    this.store.updateShard(shard.id, { files_read: merged })
    entry.progress.shards = this.shardProgress(context.runId)
    const skippedNote = rejected.length
      ? `（忽略 ${rejected.length} 个不在本切片清单内的路径）`
      : ''
    entry.progress.note = clip(input?.note, 200)
      || `已记录 ${merged.length}/${shard.file_count} 个已读文件${skippedNote}`
    this.touchProgress(context.runId)
    return {
      ok: true,
      shard: shard.name,
      recorded: reported.length,
      rejected: rejected.length,
      readCount: merged.length,
      fileCount: shard.file_count,
    }
  }

  /**
   * Pause a live run: stop the current model reply but keep the session so the
   * audit can continue from the interruption point later.
   */
  pause(runId) {
    const entry = this.active.get(runId)
    if (!entry) throw new Error('该运行已结束')
    entry.pauseRequested = true
    entry.cancelRequested = false
    entry.progress.stage = '正在暂停'
    entry.progress.note = '正在停止当前步骤，完成后可点击「继续」从中断处恢复'
    entry.progress.updatedAt = nowIso()
    this.persistProgress(runId)
    if (entry.retryTimer) {
      clearTimeout(entry.retryTimer)
      entry.retryTimer = null
      this.finish(runId, { paused: true })
      return
    }
    try {
      entry.handle.agent.cancel({ kind: 'user' })
    } catch {
      // ignore
    }
    // Fallback: the host may never report idle after a cancel (lost watcher,
    // cancelled turn). Settle anyway so the「继续」button always appears.
    if (entry.settleTimer) clearTimeout(entry.settleTimer)
    entry.settleTimer = setTimeout(() => {
      const current = this.active.get(runId)
      if (!current || !current.pauseRequested) return
      this.finish(runId, { paused: true })
    }, SETTLE_TIMEOUT_MS)
    entry.settleTimer.unref?.()
  }

  /** Continue a paused run from where it stopped, reusing the same session. */
  resume(runId) {
    const entry = this.paused.get(runId)
    if (!entry) throw new Error('该运行不在暂停状态')
    if (this.active.size >= this.limit()) throw new Error('已达到最大并发审计数，请稍后再试')
    this.paused.delete(runId)
    this.sessionRuns.set(entry.sessionId, runId)
    this.active.set(runId, entry)
    entry.pauseRequested = false
    entry.cancelRequested = false
    entry.error = null
    entry.retries = 0
    entry.idleArms = 0
    entry.eventAt = 0
    entry.epoch = (entry.epoch ?? 0) + 1
    entry.startedAt = Date.now()
    entry.followupAt = Date.now()
    entry.progress.stage = '继续审计'
    entry.progress.note = '已从暂停点继续，等待 Agent 恢复工作'
    entry.progress.updatedAt = nowIso()
    entry.progress.stalled = false
    entry.progress.idleSeconds = 0
    this.store.updateRun(runId, { status: 'running', finished_at: null, error: null, progress: { ...entry.progress } })
    this.store.updateTask(entry.taskId, { status: 'running' })
    this.startHeartbeat(runId)
    try {
      const queued = entry.handle.agent.followup(entry.createUserMessage({
        content: [{
          type: 'text',
          text: '继续。上一次审计被用户暂停，请从中断处继续完成剩余的审计工作，不要重复已经完成的部分。',
        }],
        source: { kind: 'user' },
      }))
      if (queued && typeof queued.then === 'function') {
        queued.catch(resumeError => {
          const pending = this.active.get(runId)
          if (!pending) return
          pending.error = String(resumeError?.message ?? resumeError)
          this.scheduleRetry(runId, pending.error)
        })
      }
    } catch (error) {
      this.finish(runId, { error: String(error?.message ?? error) })
      throw error
    }
    this.watchIdle(runId)
    return this.store.getRun(runId)
  }

  /** Drop a paused run so a fresh start can create a new conversation. */
  discardPaused(taskId) {
    for (const [runId, entry] of [...this.paused]) {
      if (entry.taskId !== taskId) continue
      this.paused.delete(runId)
      this.sessionRuns.delete(entry.sessionId)
      try {
        entry.handle.dispose()
      } catch {
        // ignore
      }
      this.store.updateRun(runId, {
        status: 'cancelled',
        finished_at: nowIso(),
        error: '暂停后重新运行，已替换为新的审计会话',
        progress: {
          ...entry.progress,
          stage: '已取消',
          note: '暂停后重新运行，已替换为新的审计会话',
          updatedAt: nowIso(),
        },
      })
      this.closeShardRecords(runId, {
        runningStatus: 'cancelled',
        pendingStatus: 'cancelled',
        note: '暂停后重新运行，已替换为新的审计会话',
      })
    }
  }

  /** Cancel an active run. */
  cancel(runId) {
    const paused = this.paused.get(runId)
    if (paused) {
      if (paused.settleTimer) {
        clearTimeout(paused.settleTimer)
        paused.settleTimer = null
      }
      this.paused.delete(runId)
      this.sessionRuns.delete(paused.sessionId)
      try {
        paused.handle.dispose()
      } catch {
        // ignore
      }
      this.finishPausedRecord(runId, paused, '运行已取消')
      return
    }
    const entry = this.active.get(runId)
    if (!entry) throw new Error('该运行已结束')
    entry.cancelRequested = true
    entry.pauseRequested = false
    entry.progress.stage = '正在取消'
    entry.progress.note = '正在停止当前审计步骤…'
    entry.progress.updatedAt = nowIso()
    this.persistProgress(runId)
    if (entry.retryTimer) {
      clearTimeout(entry.retryTimer)
      entry.retryTimer = null
      this.finish(runId, { cancelled: true })
      return
    }
    try {
      entry.handle.agent.cancel({ kind: 'user' })
    } catch {
      // ignore
    }
    if (entry.settleTimer) clearTimeout(entry.settleTimer)
    entry.settleTimer = setTimeout(() => {
      const current = this.active.get(runId)
      if (!current || !current.cancelRequested) return
      this.finish(runId, { cancelled: true })
    }, SETTLE_TIMEOUT_MS)
    entry.settleTimer.unref?.()
  }

  /** Record one session event into the run's trajectory JSONL. */
  onSessionEvent(session, event) {
    const runId = this.sessionRuns.get(session.id)
    if (!runId) return
    const entry = this.active.get(runId)
    if (!entry) return
    // Token accounting must not depend on the trajectory early-return below:
    // runs without a trajectory file still need usage totals and budget checks.
    accumulateUsage(entry, event)
    const run = this.store.getRun(runId)
    if (!run?.trajectory_path) return
    try {
      appendFileSync(
        run.trajectory_path,
        `${JSON.stringify({ sessionId: session.id, seq: event.seq, time: event.time, type: event.type, data: event.data })}\n`,
      )
    } catch {
      // ignore
    }
    if (event.type === 'assistant/message') {
      entry.eventAt = Date.now()
      entry.idleArms = 0
      entry.progress.lastEventAt = nowIso()
      const text = extractMessageText(event.data?.message)
      if (text) entry.assistantText = text
      this.checkTokenBudget(runId)
      this.touchProgress(runId)
    } else if (event.type === 'tool/call') {
      entry.eventAt = Date.now()
      entry.idleArms = 0
      entry.progress.lastEventAt = nowIso()
      entry.progress.toolCalls += 1
      const toolName = String(
        event.data?.name ?? event.data?.toolName ?? event.data?.title ?? '',
      ).trim()
      if (toolName) entry.progress.lastTool = clip(toolName, 60)
      // Issue #10: auto-infer coverage from read-type tool calls, and keep
      // the findings counter honest even when the model skips the report tool.
      if (READ_TOOL_PATTERN.test(toolName)) {
        const rawPath = eventFilePath(event.data)
        const matched = rawPath ? matchReadFile(entry, rawPath, this.store) : null
        if (matched) this.recordReadFiles(runId, entry, [matched])
      }
      if (FINDING_TOOL_PATTERN.test(toolName)) {
        entry.progress.findings = this.store.countFindingsForRun(runId)
      }
      this.touchProgress(runId)
    } else if (event.type === 'step/end') {
      entry.eventAt = Date.now()
      entry.idleArms = 0
      entry.progress.lastEventAt = nowIso()
      entry.progress.steps += 1
      if (entry.progress.stage === '初始化') {
        entry.progress.stage = '代码探索'
        entry.progress.note = 'Agent 正在读取代码'
        entry.progress.percent = Math.max(entry.progress.percent ?? 0, 8)
      }
      this.touchProgress(runId)
    } else if (event.type === 'turn/end') {
      entry.eventAt = Date.now()
      entry.idleArms = 0
      entry.progress.lastEventAt = nowIso()
      this.checkTokenBudget(runId)
      const reason = event.data?.reason
      if (reason?.kind === 'error') {
        const message = String(reason.error?.message ?? 'Agent 运行失败').trim()
        entry.error = message
        entry.progress.stage = '失败'
        entry.progress.note = clip(message, 200)
        this.persistProgress(runId)
        // `whenIdle` resolves for failed turns too; idle handling decides
        // whether to auto-continue or fail the run.
      }
    }
  }

  /** Mark progress as changed and flush it to SQLite at most once per second. */
  touchProgress(runId) {
    const entry = this.active.get(runId)
    if (!entry) return
    entry.progress.updatedAt = nowIso()
    if (entry.progressTimer) return
    entry.progressTimer = setTimeout(() => {
      entry.progressTimer = null
      this.persistProgress(runId)
    }, 900)
    entry.progressTimer.unref?.()
  }

  /**
   * Enforce the per-run token budget ("maxTokensPerRun" setting, 0 =
   * unlimited). Called after usage accumulated on message/turn boundaries;
   * exceeding the budget fails the run like the duration budget does.
   */
  checkTokenBudget(runId) {
    const entry = this.active.get(runId)
    if (!entry) return
    const maxTokens = MaxTokensPerRun(
      this.store.getSetting('maxTokensPerRun', this.config.maxTokensPerRun ?? DEFAULT_MAX_TOKENS_PER_RUN),
    )
    if (maxTokens <= 0) return
    const used = (entry.progress.tokensIn ?? 0) + (entry.progress.tokensOut ?? 0)
    if (used >= maxTokens) {
      this.finish(runId, {
        error: `达到 token 预算上限 ${maxTokens}（已用约 ${used}），运行已按预算停止（进度与发现已保留）`,
      })
    }
  }

  persistProgress(runId) {
    const entry = this.active.get(runId)
    if (!entry) return
    try {
      this.store.updateRun(runId, { progress: { ...entry.progress } })
    } catch {
      // ignore
    }
  }

  /**
   * Merge auto-detected read files into the coverage ledger (issue #10).
   * Mirrors reportFiles' dedup/persist path but is driven by session events,
   * so coverage no longer depends on the model voluntarily calling
   * code_audit_report_files. No-ops silently for paths outside the audit
   * list (call chains legitimately reach outside the slice).
   */
  recordReadFiles(runId, entry, relativePaths) {
    const fresh = relativePaths.filter(path => !entry.readFiles.has(path))
    if (fresh.length === 0) return
    for (const path of fresh) entry.readFiles.add(path)
    try {
      if (entry.kind === 'shard' && entry.shardId) {
        const shard = this.store.getShard(entry.shardId)
        if (shard) {
          const merged = [...new Set([...shard.files_read, ...fresh])]
          this.store.updateShard(shard.id, { files_read: merged })
          entry.progress.shards = this.shardProgress(runId)
        }
      }
      entry.progress.readFiles = entry.readFiles.size
      // Issue #10: let the inferred coverage push the single-mode percent
      // forward even when the model never reports progress. Shard mode keeps
      // its slice-completion formula (done advances in onShardIdle).
      if (entry.kind === 'single') {
        const total = entry.auditedList?.length
        if (Number.isInteger(total) && total > 0) {
          const base = 10 + Math.round((entry.readFiles.size / total) * 75)
          entry.progress.percent = Math.max(entry.progress.percent ?? 0, Math.min(85, base))
        }
      }
      // Never clobber a stage note the model just wrote; only refresh our own.
      if (!entry.progress.note || entry.progress.note.startsWith('已自动记录读取')) {
        entry.progress.note = clip(`已自动记录读取 ${entry.readFiles.size} 个审计范围内文件`, 200)
      }
      this.touchProgress(runId)
    } catch {
      // Coverage bookkeeping must never break the audit run itself.
    }
  }

  /** Store progress reported by the audit agent during a run. */
  reportProgress(context, input) {
    const entry = this.active.get(context.runId)
    if (!entry) throw new Error('当前没有正在运行的审计')
    const progress = entry.progress
    const rawName = String(input.prompt_name ?? '').trim()
    // Issue #10: only an exact name earns type-credit; fuzzy matches are too
    // easy to game or misfire ("XSS" matching "存储型 XSS"). Fuzzy matches are
    // kept solely as a display label for stage/note text.
    const exactMatched = rawName ? entry.promptNames.find(name => name === rawName) : undefined
    const fuzzyMatched = rawName
      ? entry.promptNames.find(name => name !== rawName && (name.includes(rawName) || rawName.includes(name)))
      : undefined
    const matched = exactMatched
    const label = exactMatched || fuzzyMatched || rawName

    // In shard mode the unit is the slice, not the vulnerability type: the same
    // type list runs inside every slice, so done/total must not be rewritten by
    // per-type reports.
    if (entry.kind === 'shard' || entry.kind === 'aggregate') {
      const done = input.status === 'done'
      if (done && label && !entry.donePrompts.includes(label)) entry.donePrompts.push(label)
      progress.prompt = entry.kind === 'shard' ? progress.prompt || '' : ''
      progress.stage = entry.kind === 'shard' ? '切片审计' : '跨切片汇聚'
      progress.note = clip(input.note, 200) ||
        (entry.kind === 'shard'
          ? (done ? `已完成：${label}` : `正在审计：${label}`)
          : '正在核对跨切片污点流')
      const base = entry.kind === 'shard'
        ? 5 + Math.round(((progress.done ?? 0) / Math.max(progress.total, 1)) * 88)
        : 95
      progress.percent = Math.max(progress.percent ?? 0, Math.min(entry.kind === 'shard' ? 93 : 99, base))
      progress.updatedAt = nowIso()
      this.persistProgress(context.runId)
      return {
        percent: progress.percent,
        done: progress.done,
        total: progress.total,
        stage: progress.stage,
        note: progress.note,
      }
    }

    if (input.status === 'done') {
      if (matched && !entry.donePrompts.includes(matched)) entry.donePrompts.push(matched)
      progress.done = entry.donePrompts.length
      progress.percent = Math.min(95, 10 + Math.round((progress.done / Math.max(progress.total, 1)) * 80))
      progress.stage = progress.done >= progress.total ? '汇总' : '类型审计'
      progress.prompt = progress.done >= progress.total ? '' : label
      progress.note = clip(input.note, 200) ||
        (progress.done >= progress.total ? '全部类型审计完成，正在生成总结' : `已完成：${label}`)
    } else {
      progress.stage = '类型审计'
      progress.prompt = label
      progress.note = clip(input.note, 200) || `正在审计：${label}`
      const base = 10 + Math.round((progress.done / Math.max(progress.total, 1)) * 80)
      progress.percent = Math.max(progress.percent ?? 0, Math.min(90, base))
    }

    this.persistProgress(context.runId)
    return {
      percent: progress.percent,
      done: progress.done,
      total: progress.total,
      stage: progress.stage,
      note: progress.note,
    }
  }

  /** The active run for an agent (used by the submit tools). */
  contextForAgent(agent) {
    const sessionId = agent?.session?.id
    if (!sessionId) return undefined
    const runId = this.sessionRuns.get(sessionId)
    if (!runId) return undefined
    const run = this.store.getRun(runId)
    if (!run || run.status !== 'running') return undefined
    const entry = this.active.get(runId)
    return {
      runId,
      taskId: run.task_id,
      shardId: entry?.kind === 'shard' ? entry.shardId : undefined,
      shardName: entry?.kind === 'shard' ? entry.progress?.prompt || '' : undefined,
    }
  }

  /** Store a finding submitted by the audit agent. */
  submitFinding(context, input) {
    const task = this.store.getTask(context.taskId)
    if (!task) throw new Error('任务不存在')
    const title = clip(input.title, 200)
    if (!title) throw new Error('漏洞标题不能为空')
    const filePath = String(input.file_path ?? '').replaceAll('\\', '/')
    let lineStart = Number.isFinite(Number(input.line_start)) ? Number(input.line_start) : null
    let lineEnd = Number.isFinite(Number(input.line_end)) ? Number(input.line_end) : lineStart
    // Evidence verification (issue #3): reject hallucinated paths, line
    // numbers and snippets before they reach the database. The thrown error
    // is delivered back to the agent as a tool failure so it can re-report
    // with real evidence. Shard entries additionally pin findings to their
    // own file list; single/aggregate runs may reference any repo file.
    const entry = this.active.get(context.runId)
    const allowedFiles = entry?.kind === 'shard'
      ? new Set((entry.plan?.shards?.[entry.shardIndex]?.files ?? [])
        .map(file => String(file).replaceAll('\\', '/')))
      : undefined
    const verification = verifyFindingEvidence({
      repoPath: task.repo_path,
      filePath,
      lineStart,
      lineEnd,
      snippet: input.code_snippet,
      allowedFiles,
    })
    if (!verification.ok) throw new Error(formatEvidenceProblems(verification.problems))
    if (verification.corrected) {
      // The snippet is real but the model's line anchors drifted; store the
      // located range so reports stay accurate.
      lineStart = verification.actualLineStart
      lineEnd = verification.actualLineEnd ?? verification.actualLineStart
    }
    const skill = task.audit_mode === 'skill' && task.skill_id ? this.store.getSkill(task.skill_id) : undefined
    const prompt = skill
      ? undefined
      : input.prompt_name
        ? this.store.getPromptByName(input.prompt_name)
        : undefined
    const promptId = skill ? null : prompt?.id ?? task.prompt_ids[0] ?? null
    const skillId = skill?.id ?? null
    // Fingerprint is position+category based: wording drift in the title must
    // not spawn a duplicate record, and re-reporting the same spot updates it.
    const category = input.category || prompt?.category || skill?.category || ''
    const fingerprint = createHash('sha256')
      .update(`${context.taskId}|${filePath}|${lineStart ?? ''}|${category}`)
      .digest('hex')
      .slice(0, 24)
    const result = this.store.addFinding(context.taskId, {
      run_id: context.runId,
      shard_id: context.shardId ?? '',
      prompt_id: promptId,
      skill_id: skillId,
      title,
      severity: input.severity,
      category,
      cwe_id: String(input.cwe_id ?? '').trim(),
      confidence: ['high', 'medium', 'low'].includes(input.confidence) ? input.confidence : 'medium',
      file_path: filePath,
      line_start: lineStart,
      line_end: lineEnd,
      code_snippet: clip(input.code_snippet, 2000),
      description: String(input.description ?? ''),
      evidence: String(input.evidence ?? ''),
      recommendation: String(input.recommendation ?? ''),
      poc: clip(input.poc_request, 4000),
      fingerprint,
    })
    this.store.updateRun(context.runId, { findings_count: this.store.countFindingsForRun(context.runId) })
    if (entry) {
      entry.progress.findings = this.store.countFindingsForRun(context.runId)
      this.touchProgress(context.runId)
    }
    return result
  }

  /**
   * Problem #2 (SCA): persist dependency vulnerabilities parsed from the
   * repository manifests as findings. These are deterministic version matches,
   * not model judgment, so they are stored pre-confirmed (review_status
   * 'confirmed') — they skip the LLM review pass and always land in the main
   * report. The fingerprint is manifest+package+CVE based, so re-runs update
   * rather than duplicate. Idempotent; safe to call at run start.
   * Returns the number of dependency findings recorded.
   */
  recordDependencyFindings(runId, taskId, vulns) {
    if (!Array.isArray(vulns) || vulns.length === 0) return 0
    let recorded = 0
    for (const vuln of vulns) {
      const fingerprint = createHash('sha256')
        .update(`${taskId}|${vuln.file_path}|dep|${vuln.cve}|${vuln.package}`)
        .digest('hex')
        .slice(0, 24)
      try {
        this.store.addFinding(taskId, {
          run_id: runId,
          shard_id: '',
          prompt_id: null,
          skill_id: null,
          title: clip(vuln.title, 200),
          severity: vuln.severity,
          category: '依赖漏洞',
          cwe_id: String(vuln.cwe ?? ''),
          confidence: 'high',
          file_path: String(vuln.file_path ?? '').replaceAll('\\', '/'),
          line_start: null,
          line_end: null,
          code_snippet: '',
          description: String(vuln.description ?? ''),
          evidence: String(vuln.evidence ?? ''),
          recommendation: String(vuln.recommendation ?? ''),
          poc: '',
          fingerprint,
          review_status: 'confirmed',
          review_note: `依赖版本自动匹配（${vuln.cve}），无需人工复核`,
        })
        recorded += 1
      } catch {
        // A single bad record must not abort the batch or the run.
      }
    }
    if (recorded > 0) {
      this.store.updateRun(runId, { findings_count: this.store.countFindingsForRun(runId) })
      const entry = this.active.get(runId)
      if (entry) entry.progress.findings = this.store.countFindingsForRun(runId)
    }
    return recorded
  }

  /** Store a report the agent formatted according to the task's Skill. */
  submitSkillReport(context, content) {
    const task = this.store.getTask(context.taskId)
    if (!task || task.audit_mode !== 'skill') throw new Error('只有 Skill 模式的审计任务可以提交 Skill 报告')
    const text = String(content ?? '').trim()
    if (!text) throw new Error('Skill 报告内容不能为空')
    this.store.updateRun(context.runId, { skill_report: clip(text, 200000) })
    const entry = this.active.get(context.runId)
    if (entry) {
      entry.progress.stage = '报告'
      entry.progress.percent = Math.max(entry.progress.percent ?? 0, 98)
      entry.progress.note = '已提交 Skill 报告，等待会话结束'
      this.persistProgress(context.runId)
    }
  }

  /** Store the agent's run summary. */
  submitSummary(context, summary) {
    const entry = this.active.get(context.runId)
    if (entry) {
      entry.summary = String(summary ?? '')
      entry.progress.stage = '汇总'
      entry.progress.percent = Math.max(entry.progress.percent ?? 0, 95)
      entry.progress.note = '已提交审计总结，等待会话结束'
      this.persistProgress(context.runId)
    }
    this.store.updateRun(context.runId, { summary: clip(summary, 4000) })
  }

  /**
   * Issue #4: the review session reports verdicts for every finding of the
   * run. Only fully valid batches are written — one bad row rejects the whole
   * submission so the model can re-send a corrected batch.
   */
  submitReviewVerdict(context, input) {
    const entry = this.active.get(context?.runId)
    if (!entry || entry.kind !== 'review') {
      throw new Error('只有复核会话可以提交复核结论')
    }
    const verdicts = Array.isArray(input?.verdicts) ? input.verdicts : []
    if (verdicts.length === 0) throw new Error('复核结论不能为空')
    const allowed = ['confirmed', 'needs-review', 'rejected']
    const problems = []
    const rows = []
    for (const item of verdicts) {
      const findingId = String(item?.finding_id ?? '').trim()
      const verdict = String(item?.verdict ?? '').trim()
      if (!allowed.includes(verdict)) {
        problems.push(`未知的复核结论 ${verdict || '（空）'}（可选：${allowed.join(', ')}）`)
        continue
      }
      const finding = findingId ? this.store.getFinding(findingId) : null
      if (!finding || finding.task_id !== entry.taskId) {
        problems.push(`发现 ${findingId || '（空）'} 不存在或不属于本次审计`)
        continue
      }
      rows.push({
        findingId,
        verdict,
        note: clip(String(item?.note ?? ''), 1000),
      })
    }
    if (problems.length) throw new Error(problems.join('；'))
    for (const row of rows) {
      this.store.updateFinding(row.findingId, {
        review_status: row.verdict,
        review_note: row.note,
        reviewed_at: nowIso(),
        review_run_id: context.runId,
      })
    }
    const done = rows.length
    entry.progress.done = (entry.progress.done ?? 0) + done
    entry.progress.percent = Math.min(99, 90 + (entry.progress.done / Math.max(1, entry.progress.total)) * 9)
    entry.progress.note = `已复核 ${entry.progress.done}/${entry.progress.total} 条`
    this.persistProgress(context.runId)
    return { ok: true, reviewed: done, total: entry.progress.total }
  }

  finish(runId, { error, cancelled = false, paused = false } = {}) {
    const entry = this.active.get(runId)
    if (!entry) return
    this.active.delete(runId)
    this.clearRunTimers(entry)

    const run = this.store.getRun(runId)
    if (!run) return
    const findingsCount = this.store.countFindingsForRun(runId)
    const failure = error ?? entry.error
    const status = paused
      ? 'paused'
      : cancelled || entry.cancelRequested
        ? 'cancelled'
        : failure
          ? 'failed'
          : 'completed'
    const progress = {
      ...entry.progress,
      // A sharded run counts finished slices, a review run counts reviewed
      // findings; otherwise finished vulnerability types.
      done: entry.kind === 'shard' || entry.kind === 'aggregate' || entry.kind === 'review'
        ? entry.progress.done ?? 0
        : entry.donePrompts.length,
      findings: findingsCount,
      percent: status === 'completed' ? 100 : entry.progress.percent ?? 0,
      stage: status === 'paused'
        ? '已暂停'
        : status === 'failed'
          ? '失败'
          : status === 'cancelled'
            ? '已取消'
            : '完成',
      note: clip(
        status === 'paused'
          ? '已暂停，点击「继续」可从中断点继续审计'
          : failure || (status === 'cancelled' ? '运行已取消' : '审计完成'),
        300,
      ),
      // Issue #10: the durable coverage number comes from the inferred ledger
      // (single) or the reconciled slice ledgers (shard), never from notes.
      readFiles: entry.readFiles instanceof Set ? entry.readFiles.size : entry.progress.readFiles ?? 0,
      updatedAt: nowIso(),
    }

    // A slice run that ends without finishing must not leave slices pending.
    if (!paused && (entry.kind === 'shard' || entry.kind === 'aggregate')) {
      if (status === 'cancelled') {
        this.closeShardRecords(runId, {
          runningStatus: 'cancelled',
          pendingStatus: 'cancelled',
          note: '运行已取消',
        })
      } else if (status === 'failed') {
        this.closeShardRecords(runId, {
          runningStatus: 'failed',
          pendingStatus: 'cancelled',
          note: failure,
        })
      }
    }

    if (paused) {
      entry.pauseRequested = false
      entry.error = null
      this.paused.set(runId, entry)
    } else {
      this.sessionRuns.delete(entry.sessionId)
    }

    this.store.updateRun(runId, {
      status,
      finished_at: paused ? null : nowIso(),
      findings_count: findingsCount,
      summary: clip(entry.summary || entry.assistantText, 4000),
      error: failure ? clip(failure, 1000) : null,
      progress,
    })

    const task = this.store.getTask(run.task_id)
    if (task) {
      if (paused) {
        this.store.updateTask(task.id, { status: 'paused' })
      } else if (task.schedule_type !== 'manual' && task.enabled) {
        const next = rescheduleAfterRun(task)
        this.store.updateTask(task.id, { ...next, status: next.next_run_at ? 'scheduled' : status })
      } else {
        this.store.updateTask(task.id, { status, next_run_at: null })
      }
    }

    try {
      appendFileSync(
        run.trajectory_path ?? '',
        `${JSON.stringify({
          type: 'audit/run-end',
          time: nowIso(),
          data: { runId, status, findingsCount, summary: clip(entry.summary || entry.assistantText, 2000) },
        })}\n`,
      )
    } catch {
      // ignore
    }

    // Keep the conversation in the sidebar instead of disposing the session.
    if (!paused) this.retainSession(entry, task, run)
  }

  /** Close the record of a paused run that was cancelled instead of resumed. */
  finishPausedRecord(runId, entry, note) {
    if (entry.kind === 'shard' || entry.kind === 'aggregate') {
      this.closeShardRecords(runId, {
        runningStatus: 'cancelled',
        pendingStatus: 'cancelled',
        note,
      })
    }
    this.store.updateRun(runId, {
      status: 'cancelled',
      finished_at: nowIso(),
      error: note,
      progress: {
        ...entry.progress,
        stage: '已取消',
        note,
        updatedAt: nowIso(),
      },
    })
    const run = this.store.getRun(runId)
    const task = run ? this.store.getTask(run.task_id) : null
    if (task) this.store.updateTask(task.id, { status: 'cancelled', next_run_at: null })
  }

  /**
   * Keep the finished session alive: the client sidebar lists live sessions,
   * so disposing it removes the conversation from the menu panel. Rename it to
   * "<task name> · <time>" before retaining it.
   */
  /**
   * 确保代码目录已注册为一个 DSH 工作区（幂等）。DSH 的侧栏按会话 cwd 归组：
   * 只有存在一个 path 等于会话 cwd 的工作区，会话才会被收纳进去，否则落到
   * “未分组”。审计会话的 cwd 恒为 task.repo_path，因此在启动前把该目录注册
   * 成工作区，审计产生的所有会话就会自动归到对应工作区。best-effort：任何
   * 失败（旧版 DSH 无该控制器、目录不存在等）都静默忽略，不影响审计。
   */
  async ensureWorkspace(repoPath) {
    if (!repoPath) return
    try {
      const controller = this.ctx.get?.('workspaceController')
        ?? this.ctx.workspaceController
        ?? this.ctx.remote?.workspace
      if (!controller?.create) return
      const result = await controller.create({ path: repoPath })
      // 新创建的工作区用目录名作为标题，便于在侧栏辨认。
      const workspace = result?.workspace
      if (result?.created && workspace && !workspace.title?.()) {
        const base = repoPath.split(/[\\/]/).filter(Boolean).pop() || repoPath
        const rename = controller.rename?.({ workspaceId: workspace.id ?? workspace.id?.(), title: base })
        if (rename?.catch) rename.catch(() => {})
        else if (rename && typeof rename.then === 'function') rename.then(() => {}, () => {})
      }
    } catch {
      // 工作区归组是锦上添花，绝不让它阻断审计。
    }
  }

  retainSession(entry, task, run) {
    const session = entry.handle?.agent?.session ?? entry.handle?.session
    if (session) {
      const title = sessionTitle(task?.name, run?.started_at)
      try {
        const titles = this.ctx.get?.('sessionTitle') ?? this.ctx.sessionTitle
        const result = titles?.rename?.(session, title)
        if (result?.catch) result.catch(() => {})
      } catch {
        // Title is best-effort; keep the conversation even if renaming fails.
      }
    }
    this.retained.push({ sessionId: entry.sessionId, handle: entry.handle })
    while (this.retained.length > this.maxRetained) {
      const oldest = this.retained.shift()
      try {
        oldest.handle.dispose()
      } catch {
        // ignore
      }
    }
  }

  /** Dispose every live agent; called on plugin unload. */
  dispose() {
    for (const [runId, entry] of this.active) {
      this.clearRunTimers(entry)
      try {
        entry.handle.agent.cancel({ kind: 'disposed' })
      } catch {
        // ignore
      }
      try {
        entry.handle.dispose()
      } catch {
        // ignore
      }
      this.store.updateRun(runId, {
        status: 'cancelled',
        finished_at: nowIso(),
        error: '插件已卸载，审计运行已终止',
      })
      this.closeShardRecords(runId, {
        runningStatus: 'cancelled',
        pendingStatus: 'cancelled',
        note: '插件已卸载，审计运行已终止',
      })
    }
    this.active.clear()
    for (const [runId, entry] of this.paused) {
      this.clearRunTimers(entry)
      try {
        entry.handle.dispose()
      } catch {
        // ignore
      }
      this.store.updateRun(runId, {
        status: 'cancelled',
        finished_at: nowIso(),
        error: '插件已卸载，暂停的审计已终止',
      })
      this.closeShardRecords(runId, {
        runningStatus: 'cancelled',
        pendingStatus: 'cancelled',
        note: '插件已卸载，暂停的审计已终止',
      })
    }
    this.paused.clear()
    for (const item of this.retained) {
      try {
        item.handle.dispose()
      } catch {
        // ignore
      }
    }
    this.retained = []
    this.sessionRuns.clear()
  }
}

/** Auto-continue delay in minutes, clamped to the 24h ceiling. */
function RetryMinutes(value) {
  const minutes = Number(value)
  if (!Number.isFinite(minutes) || minutes <= 0) return 0
  return Math.min(1440, Math.floor(minutes))
}

/** How many times a failed model reply may be auto-continued. */
function RetryCount(value) {
  const count = Number(value)
  if (!Number.isFinite(count) || count <= 0) return 0
  return Math.min(100, Math.floor(count))
}

/** Session titles are limited to 120 bytes in the client. */
function clipBytes(text, maxBytes) {
  let result = ''
  for (const char of String(text)) {
    if (Buffer.byteLength(result + char, 'utf8') > maxBytes) break
    result += char
  }
  return result
}

function sessionTitle(name, startedAt) {
  const date = new Date(startedAt || Date.now())
  const pad = value => String(value).padStart(2, '0')
  const suffix = Number.isNaN(date.getTime())
    ? ''
    : ` · ${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
  const base = String(name ?? '').trim() || '代码审计'
  return `${clipBytes(base, Math.max(12, 120 - Buffer.byteLength(suffix))) || '代码审计'}${suffix}`
}

function extractMessageText(message) {
  if (!message) return ''
  const content = message.content
  if (Array.isArray(content)) {
    return content
      .filter(block => block?.type === 'text')
      .map(block => String(block.text ?? ''))
      .join('\n')
      .trim()
  }
  return typeof content === 'string' ? content.trim() : ''
}

/** Compose the single audit instruction sent to the new agent session. */
export function buildAuditPrompt(task, prompts, signals = null, scaScan = null) {  const sections = prompts.map((prompt, index) => {
    const label = `${index + 1}. ${prompt.name}（分类：${prompt.category || '未分类'}，默认级别：${prompt.default_severity}）`
    return `### ${label}\n${prompt.content.trim()}`
  })
  const signalSection = signals?.length ? formatSignalsSection(signals) : ''
  const scaSection = formatScaSection(scaScan)

  return `你是一名资深代码安全审计工程师，正在执行一个自动化的代码审计任务。

# 任务信息
- 任务名称：${task.name}
- 审计目录：${task.repo_path}
- 任务说明：${task.description || '（无）'}
${scaSection ? `\n${scaSection}\n` : ''}
${signalSection ? `\n${signalSection}\n` : ''}
# 审计范围约束
- 只审计下面列出的漏洞类型。未列出的漏洞类型一律不审计、不报告。
- 必须使用只读方式查看代码：禁止修改、创建、删除仓库中的任何文件；禁止运行 npm install / pip install 等安装命令；禁止构建、测试、运行仓库代码；禁止 git commit / git checkout 等写操作；禁止执行任何会产生副作用的命令。你唯一的"写入"通道是调用 code_audit_* 工具上报结果。
- 所有文件路径使用相对审计目录的路径，禁止使用绝对路径。
- 只报告有明确代码证据的问题；不确定、无法定位到具体代码的猜测不要上报。

# 本次启用的漏洞审计提示词
${sections.join('\n\n')}

# 进度上报（必须遵守）
- 按上面的顺序逐个类型审计，不要跳过。
- 开始审计某个类型前，调用工具 \`code_audit_report_progress\`，参数 prompt_name 为该类型名称，status 为 started。prompt_name 必须与类型名称完全一致（插件按名称精确匹配计入完成度，模糊或简称不计）。
- 完成该类型（无论是否发现问题）后再次调用，status 为 done，note 用一句话说明结果，例如"已检查 12 个文件，未发现符合条件的问题"。
- 即使忘记上报进度也不会影响统计：插件会从你的文件读取行为自动统计覆盖率，但请按要求上报，让用户看到准确的阶段说明。
- 全部类型完成后调用 \`code_audit_submit_summary\`。

# 上报方式（必须遵守）
每确认一个漏洞，调用工具 \`code_audit_submit_finding\`，参数含义：
- title：简短明确的漏洞标题
- severity：critical / high / medium / low / info 之一
- category：漏洞分类
- cwe_id：对应的 CWE 编号（如 CWE-89 注入、CWE-79 XSS、CWE-78 命令注入、CWE-502 反序列化），不确定时留空，不要编造
- confidence：置信度 high / medium / low 之一。high = 证据完整且触发路径可复现；medium = 触发路径明确但未实际复现；low = 疑似但存在不确定性
- file_path：相对路径
- line_start / line_end：证据代码所在行号（整数）
- code_snippet：关键代码片段（不超过 20 行）
- description：漏洞成因与影响
- evidence：可复现的触发路径或数据流（source → sink）
- recommendation：具体修复建议
- poc_request：可利用漏洞必须提供 PoC 请求包示例。包含（1）原始 HTTP 请求：请求行、Host、必要的 Cookie/Token/Content-Type 等 Header、Body；（2）一条把同一请求写成可直接执行的 curl 命令。仅当漏洞无法通过 HTTP 触发（如本地条件、需依赖内部状态）时留空，并在 evidence 中说明复现步骤。
- prompt_name：命中的审计提示词名称（例如 "${prompts[0]?.name ?? ''}"）

全部审计完成后，调用工具 \`code_audit_submit_summary\` 输出本次审计总结：已覆盖的漏洞类型、发现数量、未发现问题的类型及原因。
如果本次没有任何发现，也必须调用 \`code_audit_submit_summary\` 说明"未发现符合条件的问题"，不要直接结束。`
}

/**
 * Plan slices for a repository, degrading to the single-session path when the
 * repository cannot be walked (permissions, deleted path, unexpected error).
 */
function planShardsSafe(repoPath) {
  try {
    return planShards(repoPath)
  } catch {
    return null
  }
}

/** Async twin of planShardsSafe — walks off the event loop. */
async function planShardsSafeAsync(repoPath) {
  try {
    return await planShardsAsync(repoPath)
  } catch {
    return null
  }
}

/** Compose the audit instruction for one slice of a sharded audit. */
export function buildShardAuditPrompt(task, shard, workspace, prompts, signals = null, scaScan = null) {
  const sections = prompts.map((prompt, index) => {
    const label = `${index + 1}. ${prompt.name}（分类：${prompt.category || '未分类'}，默认级别：${prompt.default_severity}）`
    return `### ${label}\n${prompt.content.trim()}`
  })
  const files = shard.files ?? []
  const fileList = files.length
    ? files.map(file => `- ${file}`).join('\n')
    : '- （本切片没有可审计文件）'
  const siblings = (workspace?.siblingShards ?? []).length
    ? workspace.siblingShards.map(item => `- ${item}`).join('\n')
    : '- （无其他切片）'
  const entries = (workspace?.entryFiles ?? []).length
    ? workspace.entryFiles.map(file => `- ${file}`).join('\n')
    : '- （未识别到入口文件）'
  const signalSection = signals?.length ? formatSignalsSection(signals) : ''
  const scaSection = formatScaSection(scaScan)

  // 提示：为了让多个切片会话之间能命中 DSH 的 prompt 前缀缓存，把“所有切片
  // 完全相同”的部分（角色、通用规矩、上报方式、漏洞清单）放在最前面，把
  // “每个切片各不相同”的部分（切片信息、文件清单、兄弟切片、入口文件、
  // 静态信号）放在最后。这样共享前缀在多个切片之间逐字节一致，可被上游缓存，
  // 显著降低整次分片审计的 token 消耗。
  return `你是一名资深代码安全审计工程师，正在执行一个自动化的代码审计任务。本次任务把仓库切成了多个切片，每个切片由一个独立会话审计，你负责其中的一个切片。

# 任务信息
- 任务名称：${task.name}
- 审计目录：${task.repo_path}
- 任务说明：${task.description || '（无）'}

# 审计范围约束
- 只审计下面列出的漏洞类型。未列出的漏洞类型一律不审计、不报告。
- 你的审计对象是本切片文件清单中的文件（清单在最后）。为了追踪调用链，可以只读查看切片外的文件，但漏洞必须落在本切片清单内的文件上；发现的问题属于其他切片时不要上报，交给对应切片或最后的跨切片汇聚处理。
- 必须使用只读方式查看代码：禁止修改、创建、删除仓库中的任何文件；禁止运行 npm install / pip install 等安装命令；禁止构建、测试、运行仓库代码；禁止 git commit / git checkout 等写操作；禁止执行任何会产生副作用的命令。你唯一的"写入"通道是调用 code_audit_* 工具上报结果。
- 所有文件路径使用相对审计目录的路径，禁止使用绝对路径。
- 只报告有明确代码证据的问题；不确定、无法定位到具体代码的猜测不要上报。

# 本次启用的漏洞审计提示词
${sections.join('\n\n')}

# 已读文件清单上报（必须遵守）
- 每读完一批文件（建议 5～15 个），调用工具 \`code_audit_report_files\` 上报这批已读文件的相对路径，参数 files 为路径数组。
- 增量上报即可，重复上报同一个文件不会出错，插件会自动去重。
- 这份清单是本切片的覆盖率台账：没有上报的文件会被视为未审计。审计结束时，清单里的每一个文件都应该已上报。
- 插件同时会从你的文件读取行为自动登记覆盖率，上报清单用于对账；两者不一致时以自动登记为准。

# 进度上报（必须遵守）
- 按上面的顺序逐个类型审计，不要跳过。
- 开始审计某个类型前，调用工具 \`code_audit_report_progress\`，参数 prompt_name 为该类型名称，status 为 started。prompt_name 必须与类型名称完全一致（插件按名称精确匹配计入完成度，模糊或简称不计）。
- 完成该类型（无论是否发现问题）后再次调用，status 为 done，note 用一句话说明结果，例如"已检查 12 个文件，未发现符合条件的问题"。
- 即使忘记上报进度也不会影响统计：插件会从你的文件读取行为自动统计覆盖率，但请按要求上报，让用户看到准确的阶段说明。
- 全部类型完成后调用 \`code_audit_submit_summary\`。

# 上报方式（必须遵守）
每确认一个漏洞，调用工具 \`code_audit_submit_finding\`，参数含义：
- title：简短明确的漏洞标题
- severity：critical / high / medium / low / info 之一
- category：漏洞分类
- cwe_id：对应的 CWE 编号（如 CWE-89 注入、CWE-79 XSS、CWE-78 命令注入、CWE-502 反序列化），不确定时留空，不要编造
- confidence：置信度 high / medium / low 之一。high = 证据完整且触发路径可复现；medium = 触发路径明确但未实际复现；low = 疑似但存在不确定性
- file_path：相对路径
- line_start / line_end：证据代码所在行号（整数）
- code_snippet：关键代码片段（不超过 20 行）
- description：漏洞成因与影响
- evidence：可复现的触发路径或数据流（source → sink）
- recommendation：具体修复建议
- poc_request：可利用漏洞必须提供 PoC 请求包示例。包含（1）原始 HTTP 请求：请求行、Host、必要的 Cookie/Token/Content-Type 等 Header、Body；（2）一条把同一请求写成可直接执行的 curl 命令。仅当漏洞无法通过 HTTP 触发（如本地条件、需依赖内部状态）时留空，并在 evidence 中说明复现步骤。
- prompt_name：命中的审计提示词名称（例如 "${prompts[0]?.name ?? ''}"）
${scaSection ? `\n${scaSection}\n` : ''}
# 切片信息
- 本切片：第 ${(shard.index ?? 0) + 1} 片 / 共 ${workspace?.shardCount ?? '?'} 片
- 切片名称：${shard.name}
- 切片路径：${shard.path}
- 本切片文件数：${shard.file_count ?? files.length}
- 全仓库可审计文件数：${workspace?.totalFiles ?? '?'}

# 其他切片（不要重复审计）
${siblings}

# 本切片入口文件（建议优先从这里开始）
${entries}
${signalSection ? `\n${signalSection}\n` : ''}
# 本切片文件清单（必须逐个审计）
以下是本切片需要审计的全部文件，使用相对审计目录的路径。请逐个打开阅读，不要只抽样。
${fileList}

# 结束要求
- 确认清单中的文件都已审计并上报过已读文件清单后，调用工具 \`code_audit_submit_summary\` 输出本切片的总结：已审计文件数与覆盖比例、发现数量与概要、需要跨切片关注的问题（例如调用链延伸到其他切片但无法在本切片确认的疑点）。
- 如果本次没有任何发现，也必须调用 \`code_audit_submit_summary\` 说明"未发现符合条件的问题"，不要直接结束。`
}

/** Compose the cross-slice reconciliation instruction for a sharded audit. */
export function buildAggregatePrompt(task, plan, shards, findings) {
  const shardLines = shards.map(shard => {
    const readCount = shard.files_read?.length ?? 0
    const summary = clip(shard.summary, 1500) || '（该切片未提交总结）'
    return `## ${shard.name}（${shard.path}，${shard.file_count} 文件，已上报已读 ${readCount}，状态：${shard.status}）\n${summary}`
  }).join('\n\n')

  const findingLines = findings.length
    ? clipBytes(
      findings.map(finding => {
        const line = finding.line_start ? `:${finding.line_start}` : ''
        return `- [${finding.severity}] ${finding.title} — ${finding.file_path}${line}（${finding.category || '未分类'}）`
      }).join('\n'),
      12000,
    )
    : '（本次没有任何切片上报漏洞）'

  return `你是一名资深代码安全审计工程师。本仓库的审计已被切成 ${shards.length} 个切片，每个切片由一个独立会话完成。你的任务是做最后的跨切片核对与全局总结。

# 任务信息
- 任务名称：${task.name}
- 审计目录：${task.repo_path}
- 任务说明：${task.description || '（无）'}
- 切片策略：${plan?.strategy ?? '（未知）'}

# 各切片结果
${shardLines}

# 已提交漏洞清单
${findingLines}

# 跨切片核对任务（必须遵守）
- 使用只读方式查看代码：禁止修改、创建、删除仓库中的任何文件；禁止运行安装/构建/测试类命令；禁止 git 写操作；禁止执行任何会产生副作用的命令。所有路径使用相对审计目录的路径。
- 重点核对被切片边界截断的污点流：controller → service → dao 这类跨目录的调用链，source 在一个切片、sink 在另一个切片时，单个切片会话最容易漏报。请挑选上面切片总结里提到的疑点以及高危入口，实际打开代码确认数据流是否贯通。
- 重点核对切片之间的共享安全边界：统一认证/授权中间件、全局输入校验、反序列化入口、SQL 拼接工具类、模板渲染、文件上传处理、加解密工具。这类代码被多个切片调用，单切片视角无法判断是否所有调用点都做了校验。
- 只把确认成立的问题用 \`code_audit_submit_finding\` 上报，prompt_name 填 "跨切片汇总"；不要重复上报上面清单里已有的问题。
- 如果核对后确认没有跨切片问题，不要为了凑数上报。

# 结束要求
- 调用工具 \`code_audit_submit_summary\` 输出全局审计总结：整体风险判断、最重要的发现、切片覆盖情况（哪些切片已完成、已读文件覆盖率）、跨切片核对结论（哪些污点流已确认贯通或被排除）。`
}

/** Compose the audit instruction for a task driven by a code audit Skill. */
export function buildSkillAuditPrompt(task, skill, mirror = null) {
  const native = Boolean(mirror?.name)
  const skillSection = native
    ? `# Skill 调用（必须遵守）
本次任务使用 DSH 原生 Skill：/${mirror.name}
该 Skill 的 SKILL.md 正文由 DSH 加载；其中提到的 references/ 文件请按需读取 ${mirror.dir} 下的对应路径，不要跳过。
如果 DSH 未自动加载该 Skill，请直接读取 ${join(mirror.dir, 'SKILL.md')} 作为审计规定。`
    : `# Skill 规定（必须遵守）
${skillPromptContent(skill) || '（该 Skill 未提供具体审计规定）'}`
  const callLine = native ? `/${mirror.name}\n\n` : ''

  return `${callLine}你是一名资深代码安全审计工程师，正在按照指定的审计 Skill 执行一个自动化的代码审计任务。

# 任务信息
- 任务名称：${task.name}
- 审计目录：${task.repo_path}
- 任务说明：${task.description || '（无）'}

# 审计 Skill
- 名称：${skill.name}
- 分类：${skill.category || '未分类'}
- 说明：${skill.description || '（无）'}

${skillSection}

# 审计要求的优先级（必须遵守）
- 该 Skill 是本任务的唯一权威：审计范围、检查项、判定标准、执行步骤、工具用法、报告格式与产出位置全部严格按 Skill 执行；Skill 未要求的内容不要审计、不要报告。
- 本插件只提供附加能力（进度上报、漏洞记录、报告归档 / 导出），不得改变、简化、跳过或削弱 Skill 的任何审计要求、步骤与技巧；两者冲突时以 Skill 为准。
- Skill 要求写入文件时（例如把报告写入被审计项目的 \`reports/\`、生成清单或 PoC 文件），按 Skill 要求创建这些文件，这是只读约束的唯一例外，不得因为插件而省略该产出。
- Skill 未要求写入的场景，仍以只读方式查看代码，不要修改仓库中的其他文件，不要执行会产生副作用的命令。
- 所有文件路径使用相对审计目录的路径，禁止使用绝对路径。
- 只报告有明确代码证据的问题；不确定、无法定位到具体代码的猜测不要上报。

# 进度上报（附加能力，不影响 Skill 流程）
- 按 Skill 规定的流程审计；在不打断 Skill 步骤的前提下，开始前调用工具 \`code_audit_report_progress\`，参数 prompt_name 为 "${skill.name}"，status 为 started。
- 审计完成后再次调用，status 为 done，note 用一句话说明结果，例如"已检查 18 个文件，发现 2 个问题"。

# 漏洞记录（附加能力，不改变 Skill 判定）
每确认一个漏洞，调用工具 \`code_audit_submit_finding\`，参数含义：
- title：简短明确的漏洞标题
- severity：critical / high / medium / low / info 之一
- category：漏洞分类
- cwe_id：对应的 CWE 编号（如 CWE-89 注入、CWE-79 XSS、CWE-78 命令注入、CWE-502 反序列化），不确定时留空，不要编造
- confidence：置信度 high / medium / low 之一。high = 证据完整且触发路径可复现；medium = 触发路径明确但未实际复现；low = 疑似但存在不确定性
- file_path：相对路径
- line_start / line_end：证据代码所在行号（整数）
- code_snippet：关键代码片段（不超过 20 行）
- description：漏洞成因与影响
- evidence：可复现的触发路径或数据流（source → sink）
- recommendation：具体修复建议
- poc_request：可利用漏洞必须提供 PoC 请求包示例。包含（1）原始 HTTP 请求：请求行、Host、必要的 Cookie/Token/Content-Type 等 Header、Body；（2）一条把同一请求写成可直接执行的 curl 命令。仅当漏洞无法通过 HTTP 触发（如本地条件、需依赖内部状态）时留空，并在 evidence 中说明复现步骤。
- prompt_name：Skill 模式下无需填写。

# 结束要求
- 先完成 Skill 规定的全部步骤与产出（含 Skill 要求的文件写入 / 报告），再做插件侧归档。
- 调用 \`code_audit_submit_summary\` 输出本次审计总结：Skill 覆盖范围、发现数量、未覆盖或未发现问题的原因。
如果本次没有任何发现，也必须调用 \`code_audit_submit_summary\` 说明"未发现符合条件的问题"，不要直接结束。`
}

/**
 * Issue #4: prompt for the independent review pass. The reviewer re-derives
 * every finding from scratch instead of trusting the audit session's claims.
 */
function buildReviewPrompt(task, findings) {
  const findingLines = findings.length
    ? clipBytes(
      findings.map((finding) => {
        const line = finding.line_start ? `:${finding.line_start}` : ''
        const category = finding.category || '未分类'
        const description = clip(String(finding.description ?? ''), 300)
        const evidence = clip(String(finding.evidence ?? ''), 400)
        return [
          `- id=${finding.id}`,
          `  标题：${finding.title}（${finding.severity}，${category}，${finding.file_path}${line}）`,
          description ? `  描述：${description}` : null,
          evidence ? `  证据：${evidence}` : null,
        ].filter(Boolean).join('\n')
      }).join('\n'),
      12000,
    )
    : '（本次运行没有待复核的发现）'

  return `你是独立的安全发现复核员。下面是自动化审计会话提交的问题清单，你的职责是反向验证每一条，而不是相信原结论。

# 任务
- 任务名：${task.name}
- 代码仓库：${task.repo_path}
${task.description ? `- 任务描述：${task.description}` : ''}

# 待复核发现（共 ${findings.length} 条）
${findingLines}

# 复核方法（逐条执行）
- 反向验证触发路径：从 sink 往回找 source，确认数据流每一跳真实存在；原报告只给结论不算证据。
- 检查缓解措施：上游是否存在鉴权、参数化查询、输出编码、白名单校验、类型强制等防护使漏洞不可达。
- 检查可达性：exec/system/eval 等危险调用的入参是否其实是常量或受控拼接（不可达即否决）。
- 核对证据：报告所指文件与行号的代码是否真实存在且与描述一致；行号漂移超过 3 行且无法重新定位时按 rejected 处理。
- 只读约束：禁止修改任何文件、禁止安装依赖、禁止构建/测试/git 写操作；用只读方式查看代码。

# 上报方式
逐条调用工具 \`code_audit_submit_review\`，参数 verdicts 为数组，每项：
- finding_id：待复核发现的 id（必须逐条对应上面的 id）
- verdict：三选一
  - confirmed：触发路径完整、可复现，且缓解措施不存在
  - needs-review：无法确证也无法否决，值得人工跟进
  - rejected：无触发路径、被缓解措施阻断、或原报告与代码不符
- note：结论理由（确认时给出完整触发路径；否决时说明是哪一层防护或哪处不符）

# 结束要求
- 所有条目复核完毕后，调用 \`code_audit_submit_summary\` 总结：确认数 / 待人工数 / 否决数，以及一段整体结论。
- 一条都不要遗漏；没有把握时选 needs-review，不要猜。`
}
