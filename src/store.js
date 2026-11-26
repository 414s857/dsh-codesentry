import { mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { BUILTIN_PROMPTS } from './prompts.js'
import { BUILTIN_SKILLS } from './builtinskills.js'
import { newId, nowIso, parseJson } from './util.js'

/** SQLite-backed store for tasks, runs, findings, prompts and settings. */
export class AuditStore {
  constructor(dataDir) {
    this.dataDir = dataDir
    this.dbPath = join(dataDir, 'codesentry.db')
    mkdirSync(dirname(this.dbPath), { recursive: true })
    this.db = new DatabaseSync(this.dbPath)
    this.db.exec('PRAGMA journal_mode = WAL')
    this.db.exec('PRAGMA foreign_keys = ON')
    this.migrate()
    this.seedBuiltinPrompts()
    this.seedBuiltinSkills()
  }

  migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS prompts (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        category TEXT NOT NULL DEFAULT '',
        default_severity TEXT NOT NULL DEFAULT 'medium',
        content TEXT NOT NULL DEFAULT '',
        builtin INTEGER NOT NULL DEFAULT 0,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS skills (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        category TEXT NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '',
        content TEXT NOT NULL DEFAULT '',
        report_guide TEXT NOT NULL DEFAULT '',
        builtin INTEGER NOT NULL DEFAULT 0,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        repo_path TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        prompt_ids TEXT NOT NULL DEFAULT '[]',
        status TEXT NOT NULL DEFAULT 'draft',
        schedule_type TEXT NOT NULL DEFAULT 'manual',
        schedule_at TEXT,
        schedule_cron TEXT,
        interval_minutes INTEGER,
        next_run_at TEXT,
        enabled INTEGER NOT NULL DEFAULT 1,
        provider TEXT NOT NULL DEFAULT '',
        model TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_run_at TEXT
      );

      CREATE TABLE IF NOT EXISTS runs (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
        trigger TEXT NOT NULL DEFAULT 'manual',
        status TEXT NOT NULL DEFAULT 'running',
        started_at TEXT NOT NULL,
        finished_at TEXT,
        session_id TEXT,
        trajectory_path TEXT,
        summary TEXT,
        error TEXT,
        findings_count INTEGER NOT NULL DEFAULT 0,
        progress_json TEXT NOT NULL DEFAULT '{}'
      );
      CREATE INDEX IF NOT EXISTS idx_runs_task ON runs(task_id, started_at DESC);

      CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
        run_id TEXT REFERENCES runs(id) ON DELETE SET NULL,
        prompt_id TEXT REFERENCES prompts(id) ON DELETE SET NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'medium',
        category TEXT NOT NULL DEFAULT '',
        file_path TEXT NOT NULL DEFAULT '',
        line_start INTEGER,
        line_end INTEGER,
        code_snippet TEXT NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '',
        evidence TEXT NOT NULL DEFAULT '',
        recommendation TEXT NOT NULL DEFAULT '',
        poc TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'open',
        status_note TEXT NOT NULL DEFAULT '',
        fingerprint TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(task_id, fingerprint);
      CREATE INDEX IF NOT EXISTS idx_findings_task ON findings(task_id, created_at DESC);

      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS shards (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
        idx INTEGER NOT NULL,
        name TEXT NOT NULL,
        path TEXT NOT NULL DEFAULT '.',
        file_count INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        files_json TEXT NOT NULL DEFAULT '[]',
        read_json TEXT NOT NULL DEFAULT '[]',
        summary TEXT NOT NULL DEFAULT '',
        error TEXT,
        session_id TEXT,
        started_at TEXT,
        finished_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_shards_run ON shards(run_id, idx);

      CREATE TABLE IF NOT EXISTS run_findings (
        run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
        fingerprint TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (run_id, fingerprint)
      );
      CREATE INDEX IF NOT EXISTS idx_run_findings_task ON run_findings(task_id, run_id);
    `)
    this.ensureColumn('findings', 'shard_id', "TEXT NOT NULL DEFAULT ''")
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_findings_shard ON findings(shard_id);')
    this.ensureColumn('runs', 'progress_json', "TEXT NOT NULL DEFAULT '{}'")
    this.ensureColumn('runs', 'skill_report', "TEXT NOT NULL DEFAULT ''")
    this.ensureColumn('findings', 'poc', "TEXT NOT NULL DEFAULT ''")
    this.ensureColumn('findings', 'cwe_id', "TEXT NOT NULL DEFAULT ''")
    this.ensureColumn('findings', 'confidence', "TEXT NOT NULL DEFAULT 'medium'")
    this.ensureColumn('findings', 'skill_id', "TEXT NOT NULL DEFAULT ''")
    // Issue #4: secondary review verdicts.
    this.ensureColumn('findings', 'review_status', "TEXT NOT NULL DEFAULT 'pending'")
    this.ensureColumn('findings', 'review_note', "TEXT NOT NULL DEFAULT ''")
    this.ensureColumn('findings', 'reviewed_at', 'TEXT')
    this.ensureColumn('findings', 'review_run_id', "TEXT NOT NULL DEFAULT ''")
    this.ensureColumn('tasks', 'audit_mode', "TEXT NOT NULL DEFAULT 'prompts'")
    this.ensureColumn('tasks', 'skill_id', "TEXT NOT NULL DEFAULT ''")
    this.ensureColumn('skills', 'skill_md', "TEXT NOT NULL DEFAULT ''")
    this.ensureColumn('skills', 'references_json', "TEXT NOT NULL DEFAULT '[]'")
    this.ensureColumn('skills', 'manifest_json', "TEXT NOT NULL DEFAULT '{}'")
  }

  /** Add a column to an existing table when an older database lacks it. */
  ensureColumn(table, column, definition) {
    const columns = this.db.prepare(`PRAGMA table_info(${table})`).all()
    if (columns.some(entry => entry.name === column)) return
    this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`)
  }

  close() {
    try {
      this.db.close()
    } catch {
      // already closed
    }
  }

  // ---------------------------------------------------------------- prompts

  seedBuiltinPrompts() {
    const existing = new Set(this.db.prepare('SELECT name FROM prompts').all().map(row => row.name))
    const insert = this.db.prepare(
      `INSERT INTO prompts (id, name, category, default_severity, content, builtin, enabled, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?)`,
    )
    const stamp = nowIso()
    for (const prompt of BUILTIN_PROMPTS) {
      if (existing.has(prompt.name)) continue
      insert.run(
        newId('p'),
        prompt.name,
        prompt.category,
        prompt.default_severity,
        prompt.content,
        stamp,
        stamp,
      )
    }
  }

  /** Insert built-in demonstration skills, keeping any user edits to same-named skills. */
  seedBuiltinSkills() {
    const existing = new Set(this.db.prepare('SELECT name FROM skills').all().map(row => row.name))
    for (const skill of BUILTIN_SKILLS) {
      if (existing.has(skill.name)) continue
      this.createSkill({
        ...skill,
        skill_md: '',
        manifest: { name: skill.name, description: skill.description, category: skill.category },
        builtin: true,
        enabled: true,
      })
    }
  }

  listPrompts({ enabledOnly = false } = {}) {
    const sql = enabledOnly
      ? 'SELECT * FROM prompts WHERE enabled = 1 ORDER BY builtin DESC, name'
      : 'SELECT * FROM prompts ORDER BY builtin DESC, name'
    return this.db.prepare(sql).all().map(row => this.mapPrompt(row))
  }

  getPrompt(id) {
    const row = this.db.prepare('SELECT * FROM prompts WHERE id = ?').get(id)
    return row ? this.mapPrompt(row) : undefined
  }

  getPromptByName(name) {
    const row = this.db.prepare('SELECT * FROM prompts WHERE name = ?').get(name)
    return row ? this.mapPrompt(row) : undefined
  }

  createPrompt(input) {
    const stamp = nowIso()
    const id = newId('p')
    this.db.prepare(
      `INSERT INTO prompts (id, name, category, default_severity, content, builtin, enabled, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      id,
      input.name,
      input.category ?? '',
      input.default_severity ?? 'medium',
      input.content ?? '',
      input.builtin ? 1 : 0,
      input.enabled === false ? 0 : 1,
      stamp,
      stamp,
    )
    return this.getPrompt(id)
  }

  updatePrompt(id, patch) {
    const current = this.getPrompt(id)
    if (!current) return undefined
    this.db.prepare(
      `UPDATE prompts SET name = ?, category = ?, default_severity = ?, content = ?, enabled = ?, updated_at = ?
       WHERE id = ?`,
    ).run(
      patch.name ?? current.name,
      patch.category ?? current.category,
      patch.default_severity ?? current.default_severity,
      patch.content ?? current.content,
      patch.enabled === undefined ? (current.enabled ? 1 : 0) : patch.enabled ? 1 : 0,
      nowIso(),
      id,
    )
    return this.getPrompt(id)
  }

  deletePrompt(id) {
    const result = this.db.prepare('DELETE FROM prompts WHERE id = ?').run(id)
    return result.changes > 0
  }

  /** Insert or update a prompt by name; used by YAML import. */
  upsertPromptByName(input) {
    const existing = this.getPromptByName(input.name)
    if (existing) {
      this.updatePrompt(existing.id, {
        category: input.category ?? existing.category,
        default_severity: input.default_severity ?? existing.default_severity,
        content: input.content ?? existing.content,
        enabled: input.enabled === undefined ? existing.enabled : input.enabled,
      })
      return { prompt: this.getPrompt(existing.id), created: false }
    }
    return { prompt: this.createPrompt({ ...input, builtin: false }), created: true }
  }

  // ----------------------------------------------------------------- skills

  listSkills({ enabledOnly = false } = {}) {
    const sql = enabledOnly
      ? 'SELECT * FROM skills WHERE enabled = 1 ORDER BY builtin DESC, name'
      : 'SELECT * FROM skills ORDER BY builtin DESC, name'
    return this.db.prepare(sql).all().map(row => this.mapSkill(row))
  }

  getSkill(id) {
    const row = this.db.prepare('SELECT * FROM skills WHERE id = ?').get(id)
    return row ? this.mapSkill(row) : undefined
  }

  getSkillByName(name) {
    const row = this.db.prepare('SELECT * FROM skills WHERE name = ?').get(name)
    return row ? this.mapSkill(row) : undefined
  }

  createSkill(input) {
    const stamp = nowIso()
    const id = newId('s')
    this.db.prepare(
      `INSERT INTO skills (id, name, category, description, content, report_guide, skill_md, references_json,
        manifest_json, builtin, enabled, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      id,
      input.name,
      input.category ?? '',
      input.description ?? '',
      input.content ?? '',
      input.report_guide ?? '',
      input.skill_md ?? '',
      JSON.stringify(input.references ?? []),
      JSON.stringify(input.manifest ?? {}),
      input.builtin ? 1 : 0,
      input.enabled === false ? 0 : 1,
      stamp,
      stamp,
    )
    return this.getSkill(id)
  }

  updateSkill(id, patch) {
    const current = this.getSkill(id)
    if (!current) return undefined
    this.db.prepare(
      `UPDATE skills SET name = ?, category = ?, description = ?, content = ?, report_guide = ?,
        skill_md = ?, references_json = ?, manifest_json = ?, enabled = ?, updated_at = ? WHERE id = ?`,
    ).run(
      patch.name ?? current.name,
      patch.category ?? current.category,
      patch.description ?? current.description,
      patch.content ?? current.content,
      patch.report_guide ?? current.report_guide,
      patch.skill_md ?? current.skill_md,
      JSON.stringify(patch.references ?? current.references ?? []),
      JSON.stringify(patch.manifest ?? current.manifest ?? {}),
      patch.enabled === undefined ? (current.enabled ? 1 : 0) : patch.enabled ? 1 : 0,
      nowIso(),
      id,
    )
    return this.getSkill(id)
  }

  deleteSkill(id) {
    const result = this.db.prepare('DELETE FROM skills WHERE id = ?').run(id)
    return result.changes > 0
  }

  /** Insert or update a skill by name; used by file and backup imports. */
  upsertSkillByName(input) {
    const existing = this.getSkillByName(input.name)
    if (existing) {
      this.updateSkill(existing.id, {
        category: input.category ?? existing.category,
        description: input.description ?? existing.description,
        content: input.content ?? existing.content,
        report_guide: input.report_guide ?? existing.report_guide,
        skill_md: input.skill_md ?? existing.skill_md,
        references: input.references ?? existing.references,
        manifest: input.manifest ?? existing.manifest,
        enabled: input.enabled === undefined ? existing.enabled : input.enabled,
      })
      return { skill: this.getSkill(existing.id), created: false }
    }
    return { skill: this.createSkill({ ...input, builtin: false }), created: true }
  }

  // ------------------------------------------------------------------ tasks

  listTasks() {
    return this.db.prepare('SELECT * FROM tasks ORDER BY created_at DESC').all().map(row => this.mapTask(row))
  }

  getTask(id) {
    const row = this.db.prepare('SELECT * FROM tasks WHERE id = ?').get(id)
    return row ? this.mapTask(row) : undefined
  }

  createTask(input) {
    const stamp = nowIso()
    const id = newId('t')
    this.db.prepare(
      `INSERT INTO tasks (id, name, repo_path, description, prompt_ids, audit_mode, skill_id, status, schedule_type,
        schedule_at, schedule_cron, interval_minutes, next_run_at, enabled, provider, model, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      id,
      input.name,
      input.repo_path,
      input.description ?? '',
      JSON.stringify(input.prompt_ids ?? []),
      input.audit_mode === 'skill' ? 'skill' : 'prompts',
      input.skill_id ?? '',
      input.status ?? 'draft',
      input.schedule_type ?? 'manual',
      input.schedule_at ?? null,
      input.schedule_cron ?? null,
      input.interval_minutes ?? null,
      input.next_run_at ?? null,
      input.enabled === false ? 0 : 1,
      input.provider ?? '',
      input.model ?? '',
      stamp,
      stamp,
    )
    return this.getTask(id)
  }

  updateTask(id, patch) {
    const current = this.getTask(id)
    if (!current) return undefined
    const next = { ...current, ...patch }
    this.db.prepare(
      `UPDATE tasks SET name = ?, repo_path = ?, description = ?, prompt_ids = ?, audit_mode = ?, skill_id = ?,
        status = ?, schedule_type = ?, schedule_at = ?, schedule_cron = ?, interval_minutes = ?, next_run_at = ?,
        enabled = ?, provider = ?, model = ?, updated_at = ?, last_run_at = ?
       WHERE id = ?`,
    ).run(
      next.name,
      next.repo_path,
      next.description ?? '',
      JSON.stringify(next.prompt_ids ?? []),
      next.audit_mode === 'skill' ? 'skill' : 'prompts',
      next.skill_id ?? '',
      next.status ?? 'draft',
      next.schedule_type ?? 'manual',
      next.schedule_at ?? null,
      next.schedule_cron ?? null,
      next.interval_minutes ?? null,
      next.next_run_at ?? null,
      next.enabled ? 1 : 0,
      next.provider ?? '',
      next.model ?? '',
      nowIso(),
      next.last_run_at ?? null,
      id,
    )
    return this.getTask(id)
  }

  deleteTask(id) {
    const result = this.db.prepare('DELETE FROM tasks WHERE id = ?').run(id)
    return result.changes > 0
  }

  /** Tasks whose schedule is due, excluding ones already running. */
  dueTasks(now = nowIso()) {
    return this.db
      .prepare(
        `SELECT * FROM tasks
         WHERE enabled = 1 AND next_run_at IS NOT NULL AND next_run_at <= ? AND status NOT IN ('running', 'paused')
         ORDER BY next_run_at`,
      )
      .all(now)
      .map(row => this.mapTask(row))
  }

  // ------------------------------------------------------------------- runs

  createRun(taskId, trigger) {
    const id = newId('r')
    this.db.prepare(
      `INSERT INTO runs (id, task_id, trigger, status, started_at)
       VALUES (?, ?, ?, 'running', ?)`,
    ).run(id, taskId, trigger, nowIso())
    return this.getRun(id)
  }

  getRun(id) {
    const row = this.db.prepare('SELECT * FROM runs WHERE id = ?').get(id)
    return row ? this.mapRun(row) : undefined
  }

  listRuns(taskId, limit = 50) {
    const sql = taskId
      ? 'SELECT * FROM runs WHERE task_id = ? ORDER BY started_at DESC LIMIT ?'
      : 'SELECT * FROM runs ORDER BY started_at DESC LIMIT ?'
    const rows = taskId
      ? this.db.prepare(sql).all(taskId, limit)
      : this.db.prepare(sql).all(limit)
    return rows.map(row => this.mapRun(row))
  }

  activeRuns() {
    return this.db
      .prepare("SELECT * FROM runs WHERE status = 'running' ORDER BY started_at")
      .all()
      .map(row => this.mapRun(row))
  }

  pausedRuns() {
    return this.db
      .prepare("SELECT * FROM runs WHERE status = 'paused' ORDER BY started_at")
      .all()
      .map(row => this.mapRun(row))
  }

  updateRun(id, patch) {
    const current = this.getRun(id)
    if (!current) return undefined
    const next = { ...current, ...patch }
    this.db.prepare(
      `UPDATE runs SET status = ?, finished_at = ?, session_id = ?, trajectory_path = ?, summary = ?,
        error = ?, findings_count = ?, progress_json = ?, skill_report = ?
       WHERE id = ?`,
    ).run(
      next.status,
      next.finished_at ?? null,
      next.session_id ?? null,
      next.trajectory_path ?? null,
      next.summary ?? null,
      next.error ?? null,
      next.findings_count ?? 0,
      JSON.stringify(next.progress ?? {}),
      next.skill_report ?? '',
      id,
    )
    return this.getRun(id)
  }

  deleteRun(id) {
    const run = this.getRun(id)
    if (!run) return undefined
    this.db.prepare('DELETE FROM runs WHERE id = ?').run(id)
    return run
  }

  countFindingsForRun(runId) {
    const row = this.db.prepare('SELECT COUNT(*) AS count FROM findings WHERE run_id = ?').get(runId)
    return Number(row?.count ?? 0)
  }

  /** Per-run fingerprint ledger: which fingerprints were reported in which run. */
  recordRunFinding(runId, taskId, fingerprint, stamp) {
    if (!runId || !fingerprint) return
    this.db
      .prepare('INSERT OR IGNORE INTO run_findings (run_id, task_id, fingerprint, created_at) VALUES (?, ?, ?, ?)')
      .run(runId, taskId, fingerprint, stamp)
  }

  /** Fingerprints reported in a given run (from the per-run ledger). */
  listRunFingerprints(runId) {
    return this.db
      .prepare('SELECT fingerprint FROM run_findings WHERE run_id = ?')
      .all(runId)
      .map(row => row.fingerprint)
  }

  // --------------------------------------------------------------- findings

  addFinding(taskId, input) {
    const stamp = nowIso()
    const fingerprint = input.fingerprint
    const existing = this.db
      .prepare('SELECT id, cwe_id, confidence FROM findings WHERE task_id = ? AND fingerprint = ?')
      .get(taskId, fingerprint)
    if (existing) {
      // Keep previously stored cwe/confidence when a re-report omits them,
      // so an update never silently erases classification fields.
      const cweId = input.cwe_id !== undefined ? String(input.cwe_id ?? '') : existing.cwe_id
      const confidence = input.confidence !== undefined && ['high', 'medium', 'low'].includes(input.confidence)
        ? input.confidence
        : existing.confidence
      this.db.prepare(
        `UPDATE findings SET description = ?, evidence = ?, recommendation = ?, poc = ?, code_snippet = ?,
          severity = ?, category = ?, file_path = ?, line_start = ?, line_end = ?, prompt_id = ?, skill_id = ?,
          shard_id = ?, cwe_id = ?, confidence = ?, run_id = ?, updated_at = ?
         WHERE id = ?`,
      ).run(
        input.description ?? '',
        input.evidence ?? '',
        input.recommendation ?? '',
        input.poc ?? '',
        input.code_snippet ?? '',
        input.severity ?? 'medium',
        input.category ?? '',
        input.file_path ?? '',
        input.line_start ?? null,
        input.line_end ?? null,
        input.prompt_id ?? null,
        input.skill_id ?? '',
        input.shard_id ?? '',
        cweId,
        confidence,
        input.run_id ?? null,
        stamp,
        existing.id,
      )
      this.recordRunFinding(input.run_id, taskId, fingerprint, stamp)
      return { finding: this.getFinding(existing.id), created: false }
    }
    const id = newId('f')
    // review_status/review_note are usually left to the default ('pending'), but
    // deterministic findings (dependency/SCA matches) may be pre-confirmed at
    // creation so they skip the LLM review pass.
    const reviewStatus = ['pending', 'confirmed', 'needs-review', 'rejected'].includes(input.review_status)
      ? input.review_status
      : 'pending'
    this.db.prepare(
      `INSERT INTO findings (id, task_id, run_id, prompt_id, skill_id, shard_id, title, severity, category, file_path,
        line_start, line_end, code_snippet, description, evidence, recommendation, poc, cwe_id, confidence,
        status, status_note, fingerprint, review_status, review_note, reviewed_at, review_run_id, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', '', ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      id,
      taskId,
      input.run_id ?? null,
      input.prompt_id ?? null,
      input.skill_id ?? '',
      input.shard_id ?? '',
      input.title,
      input.severity ?? 'medium',
      input.category ?? '',
      input.file_path ?? '',
      input.line_start ?? null,
      input.line_end ?? null,
      input.code_snippet ?? '',
      input.description ?? '',
      input.evidence ?? '',
      input.recommendation ?? '',
      input.poc ?? '',
      String(input.cwe_id ?? ''),
      input.confidence ?? 'medium',
      fingerprint,
      reviewStatus,
      reviewStatus === 'pending' ? '' : String(input.review_note ?? ''),
      reviewStatus === 'pending' ? null : stamp,
      reviewStatus === 'pending' ? '' : String(input.review_run_id ?? input.run_id ?? ''),
      stamp,
      stamp,
    )
    this.recordRunFinding(input.run_id, taskId, fingerprint, stamp)
    return { finding: this.getFinding(id), created: true }
  }

  getFinding(id) {
    const row = this.db.prepare('SELECT * FROM findings WHERE id = ?').get(id)
    return row ? this.mapFinding(row) : undefined
  }

  listFindings({ taskId, runId, status, severity, reviewStatus } = {}) {
    const clauses = []
    const params = []
    if (taskId) {
      clauses.push('task_id = ?')
      params.push(taskId)
    }
    if (runId) {
      clauses.push('run_id = ?')
      params.push(runId)
    }
    if (status) {
      clauses.push('status = ?')
      params.push(status)
    }
    if (severity) {
      clauses.push('severity = ?')
      params.push(severity)
    }
    if (reviewStatus) {
      clauses.push('review_status = ?')
      params.push(reviewStatus)
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : ''
    return this.db
      .prepare(`SELECT * FROM findings ${where} ORDER BY created_at DESC`)
      .all(...params)
      .map(row => this.mapFinding(row))
  }

  updateFinding(id, patch) {
    const current = this.getFinding(id)
    if (!current) return undefined
    // Explicit key presence decides the value: a key present in `patch` wins
    // even when its value is `null`/`''` (so callers can clear a note, reset a
    // review verdict to `pending`, or unset `reviewed_at`). Only an omitted key
    // falls back to the stored value. Using `??` here made those clears
    // impossible because an empty string never overrode the old value while an
    // explicit `null` was silently replaced by `current[field]` too.
    const pick = (key, fallback) =>
      Object.prototype.hasOwnProperty.call(patch, key) ? patch[key] : fallback
    this.db.prepare(
      `UPDATE findings SET status = ?, status_note = ?, updated_at = ?,
        review_status = ?, review_note = ?, reviewed_at = ?, review_run_id = ? WHERE id = ?`,
    ).run(
      pick('status', current.status),
      pick('status_note', current.status_note),
      nowIso(),
      pick('review_status', current.review_status),
      pick('review_note', current.review_note),
      pick('reviewed_at', current.reviewed_at),
      pick('review_run_id', current.review_run_id),
      id,
    )
    return this.getFinding(id)
  }

  deleteFinding(id) {
    const result = this.db.prepare('DELETE FROM findings WHERE id = ?').run(id)
    return result.changes > 0
  }

  // ----------------------------------------------------------------- shards

  createShard(runId, taskId, shard) {
    const id = newId('s')
    this.db.prepare(
      `INSERT INTO shards (id, run_id, task_id, idx, name, path, file_count, status, files_json, read_json, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, '[]', ?, ?)`,
    ).run(
      id,
      runId,
      taskId,
      shard.index,
      shard.name,
      shard.path ?? '.',
      shard.fileCount ?? shard.files?.length ?? 0,
      JSON.stringify(shard.files ?? []),
      nowIso(),
      nowIso(),
    )
    return this.getShard(id)
  }

  getShard(id) {
    const row = this.db.prepare('SELECT * FROM shards WHERE id = ?').get(id)
    return row ? this.mapShard(row) : undefined
  }

  listShards(runId) {
    return this.db
      .prepare('SELECT * FROM shards WHERE run_id = ? ORDER BY idx')
      .all(runId)
      .map(row => this.mapShard(row))
  }

  updateShard(id, patch) {
    const current = this.getShard(id)
    if (!current) return undefined
    const next = { ...current, ...patch }
    this.db.prepare(
      `UPDATE shards SET status = ?, files_json = ?, read_json = ?, summary = ?, error = ?, session_id = ?,
        started_at = ?, finished_at = ?, updated_at = ?
       WHERE id = ?`,
    ).run(
      next.status ?? 'pending',
      JSON.stringify(next.files ?? []),
      JSON.stringify(next.files_read ?? []),
      next.summary ?? '',
      next.error ?? null,
      next.session_id ?? null,
      next.started_at ?? null,
      next.finished_at ?? null,
      nowIso(),
      id,
    )
    return this.getShard(id)
  }

  countShards({ runId, status } = {}) {
    const clauses = []
    const params = []
    if (runId) {
      clauses.push('run_id = ?')
      params.push(runId)
    }
    if (status) {
      clauses.push('status = ?')
      params.push(status)
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : ''
    const row = this.db.prepare(`SELECT COUNT(*) AS count FROM shards ${where}`).get(...params)
    return Number(row?.count ?? 0)
  }

  // --------------------------------------------------------------- settings

  getSetting(key, fallback) {
    const row = this.db.prepare('SELECT value FROM settings WHERE key = ?').get(key)
    return row ? parseJson(row.value, fallback) : fallback
  }

  setSetting(key, value) {
    this.db
      .prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
      .run(key, JSON.stringify(value))
    return value
  }

  allSettings(defaults = {}) {
    const rows = this.db.prepare('SELECT key, value FROM settings').all()
    const stored = {}
    for (const row of rows) stored[row.key] = parseJson(row.value, null)
    return { ...defaults, ...stored }
  }

  // ----------------------------------------------------------------- mappers

  mapPrompt(row) {
    return {
      id: row.id,
      name: row.name,
      category: row.category,
      default_severity: row.default_severity,
      content: row.content,
      builtin: Boolean(row.builtin),
      enabled: Boolean(row.enabled),
      created_at: row.created_at,
      updated_at: row.updated_at,
    }
  }

  mapSkill(row) {
    return {
      id: row.id,
      name: row.name,
      category: row.category,
      description: row.description,
      content: row.content,
      report_guide: row.report_guide ?? '',
      skill_md: row.skill_md ?? '',
      references: parseJson(row.references_json, []),
      manifest: parseJson(row.manifest_json, {}),
      builtin: Boolean(row.builtin),
      enabled: Boolean(row.enabled),
      created_at: row.created_at,
      updated_at: row.updated_at,
    }
  }

  mapTask(row) {
    return {
      id: row.id,
      name: row.name,
      repo_path: row.repo_path,
      description: row.description,
      prompt_ids: parseJson(row.prompt_ids, []),
      audit_mode: row.audit_mode === 'skill' ? 'skill' : 'prompts',
      skill_id: row.skill_id ?? '',
      status: row.status,
      schedule_type: row.schedule_type,
      schedule_at: row.schedule_at,
      schedule_cron: row.schedule_cron,
      interval_minutes: row.interval_minutes,
      next_run_at: row.next_run_at,
      enabled: Boolean(row.enabled),
      provider: row.provider,
      model: row.model,
      created_at: row.created_at,
      updated_at: row.updated_at,
      last_run_at: row.last_run_at,
    }
  }

  mapRun(row) {
    return {
      id: row.id,
      task_id: row.task_id,
      trigger: row.trigger,
      status: row.status,
      started_at: row.started_at,
      finished_at: row.finished_at,
      session_id: row.session_id,
      trajectory_path: row.trajectory_path,
      summary: row.summary,
      error: row.error,
      findings_count: Number(row.findings_count ?? 0),
      progress: parseJson(row.progress_json, {}),
      skill_report: row.skill_report ?? '',
    }
  }

  mapFinding(row) {
    return {
      id: row.id,
      task_id: row.task_id,
      run_id: row.run_id,
      prompt_id: row.prompt_id,
      skill_id: row.skill_id ?? '',
      shard_id: row.shard_id ?? '',
      title: row.title,
      severity: row.severity,
      category: row.category,
      file_path: row.file_path,
      line_start: row.line_start,
      line_end: row.line_end,
      code_snippet: row.code_snippet,
      description: row.description,
      evidence: row.evidence,
      recommendation: row.recommendation,
      poc: row.poc ?? '',
      cwe_id: row.cwe_id ?? '',
      confidence: row.confidence ?? 'medium',
      status: row.status,
      status_note: row.status_note,
      review_status: row.review_status ?? 'pending',
      review_note: row.review_note ?? '',
      reviewed_at: row.reviewed_at ?? null,
      review_run_id: row.review_run_id ?? '',
      fingerprint: row.fingerprint,
      created_at: row.created_at,
      updated_at: row.updated_at,
    }
  }

  mapShard(row) {
    return {
      id: row.id,
      run_id: row.run_id,
      task_id: row.task_id,
      index: Number(row.idx ?? 0),
      name: row.name,
      path: row.path ?? '.',
      file_count: Number(row.file_count ?? 0),
      status: row.status,
      files: parseJson(row.files_json, []),
      files_read: parseJson(row.read_json, []),
      summary: row.summary ?? '',
      error: row.error ?? null,
      session_id: row.session_id ?? null,
      started_at: row.started_at ?? null,
      finished_at: row.finished_at ?? null,
      created_at: row.created_at,
      updated_at: row.updated_at,
    }
  }
}
