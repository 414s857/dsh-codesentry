import { readdirSync, readFileSync, statSync } from 'node:fs'
import { readdir, readFile, stat } from 'node:fs/promises'
import { join, relative, sep } from 'node:path'

/**
 * Repository sharding for large code audits.
 *
 * A single agent session cannot read a whole mid-size+ repository, so the run
 * is split into module shards: each shard is a small set of files audited in
 * its own session with its own "files read" ledger, and an aggregation pass
 * merges the per-shard results. Pure functions, no side effects.
 */

/** Directories that never carry auditable first-party code. */
const IGNORED_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg', 'dist', 'build', 'out', 'output',
  'target', 'vendor', 'coverage', '__pycache__', '.venv', 'venv', 'env',
  '.next', '.nuxt', '.turbo', '.cache', '.idea', '.vscode', '.gradle',
  'bin', 'obj', '.pytest_cache', '.mypy_cache', 'tmp', 'temp', 'logs',
])

/** Binary / asset extensions the audit never needs to read. */
const IGNORED_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.tiff', '.svgz',
  '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.flv', '.wav', '.flac', '.ogg',
  '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar', '.jar', '.war',
  '.exe', '.dll', '.so', '.dylib', '.a', '.lib', '.o', '.obj', '.pdb',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.woff', '.woff2',
  '.ttf', '.otf', '.eot', '.bin', '.dat', '.db', '.sqlite', '.sqlite3',
  '.wasm', '.pyc', '.pyo', '.class', '.lock', '.min.js', '.min.css', '.map',
])

/** Hard caps so a pathological tree can never stall the plugin. */
const MAX_WALK_FILES = 20000
const DEFAULT_SHARD_FILE_COUNT = 120
const DEFAULT_MAX_SHARDS = 12
/** Files larger than this are skipped: reading them wastes the session budget. */
const MAX_FILE_BYTES = 400 * 1024

/** Source-code-ish extensions that indicate an auditable file. */
const CODE_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.cts', '.mts',
  '.py', '.rb', '.go', '.rs', '.java', '.kt', '.kts', '.scala', '.groovy',
  '.php', '.c', '.h', '.cpp', '.cc', '.cxx', '.hpp', '.hh', '.cs',
  '.swift', '.m', '.mm', '.dart', '.lua', '.pl', '.pm', '.sh', '.bash', '.zsh',
  '.ps1', '.psm1', '.bat', '.cmd', '.sql', '.html', '.htm', '.vue', '.svelte',
  '.astro', '.erb', '.ejs', '.hbs', '.pug', '.jinja', '.jinja2', '.tpl',
  '.css', '.scss', '.sass', '.less', '.styl', '.json', '.yml', '.yaml',
  '.toml', '.ini', '.cfg', '.conf', '.env', '.xml', '.gradle', '.proto',
  '.graphql', '.gql', '.tf', '.hcl', '.dockerfile', '.mk', '.cmake', '.ipynb',
  '.asm', '.s', '.vb', '.r', '.jl', '.ex', '.exs', '.erl', '.hrl', '.clj',
  '.cljs', '.edn', '.nim', '.zig', '.v', '.sol', '.move', '.hpp', '.ipp',
])

export const SHARD_STATUS_LABELS = {
  pending: '待审计',
  running: '审计中',
  completed: '已完成',
  failed: '失败',
  cancelled: '已取消',
}

/**
 * Plan shards for a repository.
 *
 * @param {string} repoPath absolute repository root
 * @param {{ shardFileCount?: number, maxShards?: number }} [options]
 * @returns {{
 *   mode: 'single' | 'sharded',
 *   strategy: string,
 *   truncated: boolean,
 *   totalFiles: number,
 *   shards: Array<{ index: number, name: string, path: string, fileCount: number, files: string[] }>,
 * }}
 * `files` entries are repo-relative POSIX paths; `path` is the shard's
 * dominating directory ('.' when mixed). `single` mode means the caller can
 * fall back to the legacy one-session audit untouched.
 */
export async function planShardsAsync(repoPath, options = {}) {
  const shardFileCount = clampPositive(options.shardFileCount, DEFAULT_SHARD_FILE_COUNT, 20, 1000)
  const maxShards = clampPositive(options.maxShards, DEFAULT_MAX_SHARDS, 2, 64)
  const files = await walkRepositoryAsync(repoPath)
  return planShardsFromFiles(files, shardFileCount, maxShards)
}

export function planShards(repoPath, options = {}) {
  const shardFileCount = clampPositive(options.shardFileCount, DEFAULT_SHARD_FILE_COUNT, 20, 1000)
  const maxShards = clampPositive(options.maxShards, DEFAULT_MAX_SHARDS, 2, 64)
  const files = walkRepository(repoPath)
  return planShardsFromFiles(files, shardFileCount, maxShards)
}

function planShardsFromFiles(files, shardFileCount, maxShards) {
  if (files.length <= shardFileCount) {
    return {
      mode: 'single',
      strategy: `仓库共 ${files.length} 个可审计文件，无需分片，单会话完成`,
      truncated: false,
      totalFiles: files.length,
      shards: [{
        index: 0,
        name: 'whole-repo',
        path: '.',
        fileCount: files.length,
        files: files.map(file => file.path),
      }],
    }
  }

  // Cluster by the top-level directory that dominates each file's path so
  // every shard stays inside one module — cross-module taint flows are the
  // aggregation pass's job, not the shard's.
  const groups = new Map()
  for (const file of files) {
    const parts = file.path.split('/')
    const top = parts.length > 1 ? parts[0] : '.'
    let group = groups.get(top)
    if (!group) {
      group = []
      groups.set(top, group)
    }
    group.push(file)
  }

  const shards = []
  const oversized = []
  for (const [top, group] of groups) {
    if (group.length <= shardFileCount) {
      shards.push(makeShard(top, top, group))
      continue
    }
    // A module bigger than one shard is subdivided by its second-level
    // directory; if that still overflows, fall back to alphabetical chunks.
    const subGroups = new Map()
    for (const file of group) {
      const parts = file.path.split('/')
      const sub = parts.length > 2 ? `${parts[0]}/${parts[1]}` : parts[0]
      let bucket = subGroups.get(sub)
      if (!bucket) {
        bucket = []
        subGroups.set(sub, bucket)
      }
      bucket.push(file)
    }
    for (const [sub, bucket] of subGroups) {
      if (bucket.length <= shardFileCount) {
        shards.push(makeShard(sub, sub, bucket))
        continue
      }
      // Alphabetical chunks: deterministic, contiguous, never exceeds the cap.
      // Each chunk becomes its own shard: accumulating leftovers across
      // sub-modules would both break the size cap and mislabel files from one
      // sub-module with another sub-module's name.
      const chunks = chunkFiles(bucket, shardFileCount)
      chunks.forEach((chunk, chunkIndex) => {
        const label = chunks.length > 1 ? `${sub} #${chunkIndex + 1}` : sub
        shards.push(makeShard(label, sub, chunk))
      })
    }
    oversized.push(top)
  }

  // Deterministic order: by first file path of each shard.
  shards.sort((left, right) => (left.files[0] ?? '').localeCompare(right.files[0] ?? ''))
  const renumbered = shards.map((shard, index) => ({ ...shard, index }))

  // Too many modules: merge the smallest neighbours until under the cap.
  const capped = capShardCount(renumbered, maxShards)
  const truncated = files.length >= MAX_WALK_FILES
  const strategy = truncated
    ? `仓库过大（≥${MAX_WALK_FILES} 文件），扫描被截断；按顶层模块聚类为 ${capped.length} 个切片（上限 ${maxShards}），单切片 ≤ ${shardFileCount} 文件`
    : `仓库共 ${files.length} 个可审计文件，按顶层模块聚类为 ${capped.length} 个切片（上限 ${maxShards}），单切片 ≤ ${shardFileCount} 文件`
  return {
    mode: 'sharded',
    strategy,
    truncated,
    totalFiles: files.length,
    shards: capped,
    oversizedModules: oversized.length ? oversized : undefined,
  }
}

/**
 * Extra context a shard prompt needs about the whole repository: the other
 * shards' names and the repo-level entry files, so the session knows where
 * its slice sits and which files belong to the aggregation pass.
 */
export function buildShardWorkspaceInfo(plan, shard) {
  const others = plan.shards
    .filter(item => item.index !== shard.index)
    .map(item => `${item.name}（${item.fileCount} 文件，路径前缀 ${item.path}）`)
  const entryFiles = plan.shards
    .flatMap(item => item.files)
    .filter(isEntryFile)
    .slice(0, 20)
  return {
    mode: plan.mode,
    strategy: plan.strategy,
    totalFiles: plan.totalFiles,
    shardCount: plan.shards.length,
    siblingShards: others,
    entryFiles,
  }
}

// ------------------------------------------------------------------ internals

/**
 * Minimal .gitignore support (problem #7): patterns are collected per
 * directory while walking, and checked for every candidate file. Covers the
 * common grammar: `*`, `**`, `?`, `[...]`, trailing `/` (dir-only), leading
 * or embedded `/` (repo/subdir-relative), `!` negation, comments, blank
 * lines. Later patterns win, matching git's last-match-wins semantics.
 */
function parseGitignore(text, baseDir) {
  const rules = []
  for (const rawLine of String(text ?? '').split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    let negated = false
    let body = line
    if (body.startsWith('!')) { negated = true; body = body.slice(1) }
    // Trailing spaces are insignificant unless escaped; git strips them.
    body = body.replace(/(?<!\\)\s+$/, '')
    if (!body) continue
    const dirOnly = body.endsWith('/')
    if (dirOnly) body = body.slice(0, -1)
    // A pattern containing a slash (other than a trailing one) anchors to the
    // directory holding the .gitignore; otherwise it matches at any depth.
    const anchored = body.includes('/')
    rules.push({
      negated,
      dirOnly,
      anchored,
      // Relative base for anchored patterns; '' means the .gitignore's dir.
      base: anchored ? baseDir : '',
      // Leading '/' is redundant once anchored; strip it.
      pattern: body.startsWith('/') ? body.slice(1) : body,
      regex: globToRegExp(body.startsWith('/') ? body.slice(1) : body),
    })
  }
  return rules
}

/** gitignore-style glob → RegExp. `**` crosses directory separators. */
function globToRegExp(pattern) {
  let source = ''
  let index = 0
  while (index < pattern.length) {
    const ch = pattern[index]
    if (ch === '*') {
      if (pattern[index + 1] === '*') {
        // `**/` at start → match zero or more leading directories; `/**/`
        // inside → cross-directory; bare `**` → anything.
        if (index === 0 && pattern[index + 2] === '/') { source += '(?:[^/]+/)*'; index += 3; continue }
        if (pattern[index + 2] === '/') { source += '(?:.*/)?'; index += 3; continue }
        source += '.*'
        index += 2
        continue
      }
      source += '[^/]*'
      index += 1
      continue
    }
    if (ch === '?') { source += '[^/]'; index += 1; continue }
    if (ch === '[') {
      const close = pattern.indexOf(']', index + 1)
      if (close > index) {
        let body = pattern.slice(index + 1, close)
        const negatedClass = body.startsWith('!') || body.startsWith('^')
        if (negatedClass) body = body.slice(1)
        // Escape regex-special chars inside the class except ranges.
        const escaped = body.replace(/[\\\]]/g, '\\$&')
        source += `[${negatedClass ? '^' : ''}${escaped}]`
        index = close + 1
        continue
      }
    }
    source += ch.replace(/[.+^${}()|\\*?\[\]]/g, '\\$&')
    index += 1
  }
  return new RegExp(`^${source}$`)
}

/** Check one relative path (posix, no trailing slash) against collected rules. */
function isIgnoredByGitignore(rules, relativePath, isDir) {
  const posixPath = relativePath.replaceAll('\\', '/')
  const segments = posixPath.split('/')
  let ignored = false
  for (const rule of rules) {
    let matched = false
    if (rule.anchored) {
      // Anchored rules apply to paths under the .gitignore's directory.
      const prefix = rule.base ? `${rule.base}/` : ''
      if (posixPath.startsWith(prefix)) {
        const testPath = posixPath.slice(prefix.length)
        const testSegments = testPath.split('/')
        if (rule.regex.test(testPath) && (isDir || !rule.dirOnly)) matched = true
        if (!matched) {
          // An ignored directory swallows everything under it.
          for (let i = 1; i < testSegments.length && !matched; i++) {
            if (rule.regex.test(testSegments.slice(0, i).join('/'))) matched = true
          }
        }
      }
    } else {
      // Unanchored patterns match a basename at any depth (git semantics).
      if (rule.regex.test(segments[segments.length - 1]) && (isDir || !rule.dirOnly)) matched = true
      if (!matched) {
        for (let i = 0; i < segments.length - 1 && !matched; i++) {
          if (rule.regex.test(segments[i])) matched = true
        }
      }
    }
    if (matched) ignored = !rule.negated
  }
  return ignored
}

function walkRepository(repoPath) {
  const files = []
  // Per-directory .gitignore rules, keyed by posix dir path ('' = root).
  const ignoreRules = new Map()

  const rulesFor = dir => {
    const key = toPosix(relative(repoPath, dir))
    if (ignoreRules.has(key)) return ignoreRules.get(key)
    // Include parent rules; the first walk call primes the root, deeper dirs
    // inherit rules from ancestors stored earlier.
    const parentKey = key.includes('/') ? key.slice(0, key.lastIndexOf('/')) : ''
    const inherited = key ? rulesFor(parentKey ? join(repoPath, parentKey) : repoPath) : []
    let rules = inherited
    try {
      const text = readFileSync(join(dir, '.gitignore'), 'utf8')
      const own = parseGitignore(text, key)
      rules = own.length ? [...inherited, ...own] : inherited
    } catch { /* no .gitignore here */ }
    ignoreRules.set(key, rules)
    return rules
  }

  const walk = (dir, dirKey) => {
    if (files.length >= MAX_WALK_FILES) return
    const rules = rulesFor(dir)
    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of entries) {
      if (files.length >= MAX_WALK_FILES) return
      if (entry.name.startsWith('.') && entry.name !== '.env' && entry.name !== '.htaccess') continue
      if (IGNORED_DIRS.has(entry.name.toLowerCase())) continue
      const full = join(dir, entry.name)
      const childKey = dirKey ? `${dirKey}/${entry.name}` : entry.name
      if (entry.isDirectory()) {
        if (isIgnoredByGitignore(rules, childKey, true)) continue
        walk(full, childKey)
        continue
      }
      if (!entry.isFile()) continue
      if (isIgnoredByGitignore(rules, childKey, false)) continue
      const ext = extensionOf(entry.name)
      if (IGNORED_EXTENSIONS.has(ext)) continue
      if (!isAuditableName(entry.name, ext)) continue
      let size = 0
      try {
        size = statSync(full).size
      } catch {
        continue
      }
      if (size > MAX_FILE_BYTES || size === 0) continue
      files.push({ path: toPosix(relative(repoPath, full)), size })
    }
  }
  walk(repoPath, '')
  return files
}

/**
 * Async twin of `walkRepository`. Uses `fs.promises` so a large tree does not
 * occupy the event loop, and yields between directories so the DSH host's web
 * server and other concurrent audit sessions stay responsive while a big
 * repository is scanned. Results are identical to the sync walker; the
 * breadth-first traversal order differs, but shard assignment re-groups and
 * sorts by path so downstream output is stable.
 */
async function walkRepositoryAsync(repoPath) {
  const files = []
  const ignoreRules = new Map()

  const rulesFor = async dir => {
    const key = toPosix(relative(repoPath, dir))
    if (ignoreRules.has(key)) return ignoreRules.get(key)
    const parentKey = key.includes('/') ? key.slice(0, key.lastIndexOf('/')) : ''
    const inherited = key ? await rulesFor(parentKey ? join(repoPath, parentKey) : repoPath) : []
    let rules = inherited
    try {
      const text = await readFile(join(dir, '.gitignore'), 'utf8')
      const own = parseGitignore(text, key)
      rules = own.length ? [...inherited, ...own] : inherited
    } catch { /* no .gitignore here */ }
    ignoreRules.set(key, rules)
    return rules
  }

  const walk = async (dir, dirKey) => {
    if (files.length >= MAX_WALK_FILES) return
    const rules = await rulesFor(dir)
    let entries
    try {
      entries = await readdir(dir, { withFileTypes: true })
    } catch {
      return
    }
    // Yield to the event loop once per directory so concurrent HTTP/session
    // work interleaves with the walk instead of waiting for the whole scan.
    await new Promise(resolve => setImmediate(resolve))
    for (const entry of entries) {
      if (files.length >= MAX_WALK_FILES) return
      if (entry.name.startsWith('.') && entry.name !== '.env' && entry.name !== '.htaccess') continue
      if (IGNORED_DIRS.has(entry.name.toLowerCase())) continue
      const full = join(dir, entry.name)
      const childKey = dirKey ? `${dirKey}/${entry.name}` : entry.name
      if (entry.isDirectory()) {
        if (isIgnoredByGitignore(rules, childKey, true)) continue
        await walk(full, childKey)
        continue
      }
      if (!entry.isFile()) continue
      if (isIgnoredByGitignore(rules, childKey, false)) continue
      const ext = extensionOf(entry.name)
      if (IGNORED_EXTENSIONS.has(ext)) continue
      if (!isAuditableName(entry.name, ext)) continue
      let size = 0
      try {
        size = (await stat(full)).size
      } catch {
        continue
      }
      if (size > MAX_FILE_BYTES || size === 0) continue
      files.push({ path: toPosix(relative(repoPath, full)), size })
    }
  }
  await walk(repoPath, '')
  return files
}

function isAuditableName(name, ext) {
  if (CODE_EXTENSIONS.has(ext)) return true
  // Extensionless well-known files (Makefile, Dockerfile, .env variants…).
  if (/^(makefile|dockerfile|jenkinsfile|vagrantfile|procfile|rakefile|gemfile|cmakelists\.txt)$/i.test(name)) return true
  if (/^\.env/i.test(name) || /^dockerfile/i.test(name)) return true
  return false
}

function extensionOf(name) {
  const index = name.lastIndexOf('.')
  return index <= 0 ? '' : name.slice(index).toLowerCase()
}

function isEntryFile(path) {
  const base = path.split('/').pop() ?? ''
  if (/^(index|main|app|server|entry|bootstrap|setup|wsgi|asgi|manage)\.(js|mjs|cjs|ts|tsx|jsx|py|rb|go|php)$/i.test(base)) return true
  if (/(route|router|controller|endpoint|api)/i.test(base)) return true
  return false
}

function makeShard(name, path, files) {
  return {
    index: 0,
    name,
    path,
    fileCount: files.length,
    files: files.map(file => file.path),
  }
}

/** Split a sorted list of files into fixed-size contiguous chunks. */
function chunkFiles(files, size) {
  const chunks = []
  const sorted = [...files].sort((left, right) => left.path.localeCompare(right.path))
  for (let index = 0; index < sorted.length; index += size) {
    chunks.push(sorted.slice(index, index + size))
  }
  return chunks
}

/**
 * Merge the smallest shards (nearest by first-file order) until the plan fits
 * maxShards. Merging keeps coverage complete even when modules outnumber the
 * session budget; each merged shard stays under shardFileCount where possible
 * because oversized modules were already subdivided.
 */
function capShardCount(shards, maxShards) {
  let current = [...shards]
  while (current.length > maxShards) {
    let smallestIndex = -1
    let smallestSize = Number.POSITIVE_INFINITY
    for (const [index, shard] of current.entries()) {
      if (shard.fileCount < smallestSize) {
        smallestSize = shard.fileCount
        smallestIndex = index
      }
    }
    // Merge with the neighbour that yields the smaller combined shard.
    const left = current[smallestIndex - 1]
    const right = current[smallestIndex + 1]
    const mergeWithRight = !left || (right && right.fileCount <= left.fileCount)
    const target = mergeWithRight ? smallestIndex + 1 : smallestIndex - 1
    if (target < 0 || target >= current.length) break
    const keep = Math.min(smallestIndex, target)
    const merged = {
      ...current[keep],
      name: mergeShardName(current[keep].name, current[Math.max(smallestIndex, target)].name),
      path: current[keep].path === current[Math.max(smallestIndex, target)].path
        ? current[keep].path
        : '.',
      fileCount: current[keep].fileCount + current[Math.max(smallestIndex, target)].fileCount,
      files: [...current[keep].files, ...current[Math.max(smallestIndex, target)].files],
    }
    current.splice(Math.min(smallestIndex, target), 2, merged)
  }
  return current.map((shard, index) => ({ ...shard, index }))
}

function clampPositive(value, fallback, min, max) {
  const number = Number(value)
  if (!Number.isFinite(number)) return fallback
  return Math.max(min, Math.min(max, Math.floor(number)))
}

/**
 * Merge two shard names without the label exploding: root-file shards fall
 * back to per-file names, and naive concatenation produced hundreds of
 * characters that broke the UI chips and report tables.
 */
function mergeShardName(left, right) {
  const maxPartLength = 40
  const clipPart = part => (part.length > maxPartLength ? `${part.slice(0, maxPartLength - 1)}…` : part)
  const parts = [...`${left} + ${right}`.split(' + ').map(clipPart)]
  const joined = parts.join(' + ')
  if (joined.length <= 80) return joined
  return `${parts[0]} + ${parts.length - 1} 个分片`
}

function toPosix(path) {
  return sep === '\\' ? path.replaceAll('\\', '/') : path
}
