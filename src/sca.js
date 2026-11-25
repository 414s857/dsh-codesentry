import { readFileSync, existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'

/**
 * Dependency (SCA) scanning pre-pass (problem #2 gap): the regex signal scan in
 * scan.js only looks at first-party source. Third-party components with known
 * CVEs are invisible to it, yet real projects carry a large share of their risk
 * there. This module parses the common manifest files, resolves the declared
 * versions and matches them against a small built-in advisory database.
 *
 * Scope of the built-in DB: a curated set of widely known, high-impact
 * advisories across npm / PyPI / Maven / Go. It is intentionally small and
 * offline (no network, no lockfile-of-the-internet). When a project's manifest
 * is present but a component is not in the DB, it is simply not flagged — the
 * DB is a *floor*, not a ceiling. Extend VULN_DB over time; the matching and
 * reporting machinery does not need to change.
 *
 * Matching is version-range based (a mini semver comparator), not exact-version
 * equality, so an advisory that covers "all < 4.17.21" catches older pins too.
 */

/**
 * Built-in advisory database.
 * Each entry: { ecosystem, package, cve, severity, cwe, title, range, fixed,
 *               description, recommendation }
 * `range` is a set of comparator clauses joined by space (AND); each clause is
 * `<op><version>` where op ∈ <, <=, >, >=, =. A bare version means "=version".
 * The advisory applies when the declared version satisfies every clause.
 */
const VULN_DB = [
  // ---- npm ----
  {
    ecosystem: 'npm', package: 'lodash', cve: 'CVE-2021-23337', severity: 'high', cwe: 'CWE-78',
    title: 'lodash 命令注入（template / toNumber）', range: '<4.17.21', fixed: '4.17.21',
    description: 'lodash 的 template 函数对输入过滤不严，可导致代码注入/命令注入；4.17.21 前受影响。',
    recommendation: '升级 lodash 到 4.17.21 或更高版本。',
  },
  {
    ecosystem: 'npm', package: 'lodash', cve: 'CVE-2020-8203', severity: 'high', cwe: 'CWE-1321',
    title: 'lodash 原型污染（zipObjectDeep）', range: '<4.17.19', fixed: '4.17.19',
    description: 'lodash 4.17.19 前存在原型污染漏洞，可污染 Object.prototype。',
    recommendation: '升级 lodash 到 4.17.19 或更高版本。',
  },
  {
    ecosystem: 'npm', package: 'minimist', cve: 'CVE-2021-44906', severity: 'critical', cwe: 'CWE-1321',
    title: 'minimist 原型污染', range: '<1.2.6', fixed: '1.2.6',
    description: 'minimist 1.2.6 前存在原型污染，影响参数解析。',
    recommendation: '升级 minimist 到 1.2.6 或更高版本。',
  },
  {
    ecosystem: 'npm', package: 'axios', cve: 'CVE-2021-3749', severity: 'high', cwe: 'CWE-1333',
    title: 'axios ReDoS（正则拒绝服务）', range: '<0.21.2', fixed: '0.21.2',
    description: 'axios 0.21.2 前 trim 正则存在 ReDoS，可被特制请求触发。',
    recommendation: '升级 axios 到 0.21.2 或更高版本。',
  },
  {
    ecosystem: 'npm', package: 'moment', cve: 'CVE-2022-31129', severity: 'high', cwe: 'CWE-1333',
    title: 'moment ReDoS（rfc2822 解析）', range: '<2.29.4', fixed: '2.29.4',
    description: 'moment 2.29.4 前在解析特制 RFC2822 日期字符串时存在 ReDoS。',
    recommendation: '升级 moment 到 2.29.4 或更高版本。',
  },
  {
    ecosystem: 'npm', package: 'jsonwebtoken', cve: 'CVE-2022-23529', severity: 'high', cwe: 'CWE-770',
    title: 'jsonwebtoken 密钥校验绕过风险', range: '<9.0.0', fixed: '9.0.0',
    description: 'jsonwebtoken 9.0.0 前在某些配置下存在安全校验缺陷。',
    recommendation: '升级 jsonwebtoken 到 9.0.0 或更高版本，并显式校验算法白名单。',
  },
  {
    ecosystem: 'npm', package: 'express', cve: 'CVE-2024-29041', severity: 'medium', cwe: 'CWE-601',
    title: 'Express 开放重定向/URL 处理', range: '<4.19.2', fixed: '4.19.2',
    description: 'Express 4.19.2 前 res.location 未正确编码，存在开放重定向风险。',
    recommendation: '升级 express 到 4.19.2 或更高版本。',
  },
  {
    ecosystem: 'npm', package: 'qs', cve: 'CVE-2022-24999', severity: 'high', cwe: 'CWE-1321',
    title: 'qs 原型污染 / DoS', range: '<6.10.3', fixed: '6.10.3',
    description: 'qs 6.10.3 前存在原型污染与拒绝服务缺陷。',
    recommendation: '升级 qs 到 6.10.3 或更高版本。',
  },
  {
    ecosystem: 'npm', package: 'ejs', cve: 'CVE-2022-29078', severity: 'critical', cwe: 'CWE-94',
    title: 'ejs 服务端模板注入（RCE）', range: '<3.1.7', fixed: '3.1.7',
    description: 'ejs 3.1.7 前对 settings[view options][outputFunctionName] 处理不当，可导致服务端模板注入与远程代码执行。',
    recommendation: '升级 ejs 到 3.1.7 或更高版本，禁止将用户输入拼入模板选项。',
  },
  {
    ecosystem: 'npm', package: 'tar', cve: 'CVE-2021-32804', severity: 'high', cwe: 'CWE-22',
    title: 'tar 路径遍历（解压逃逸）', range: '<6.1.2', fixed: '6.1.2',
    description: 'node-tar 6.1.2 前解压时可被构造的绝对路径/..实现目录穿越写文件。',
    recommendation: '升级 tar 到 6.1.2 或更高版本。',
  },
  // ---- PyPI ----
  {
    ecosystem: 'pypi', package: 'django', cve: 'CVE-2024-27351', severity: 'medium', cwe: 'CWE-1333',
    title: 'Django 正则拒绝服务（Truncator）', range: '<4.2.11', fixed: '4.2.11',
    description: 'Django 4.2.11 前 django.utils.text.Truncator.words() 可被特制输入触发 ReDoS。',
    recommendation: '升级 Django 到 4.2.11（或对应 LTS 的安全版本）。',
  },
  {
    ecosystem: 'pypi', package: 'requests', cve: 'CVE-2023-32681', severity: 'medium', cwe: 'CWE-200',
    title: 'requests 代理授权头泄露', range: '<2.31.0', fixed: '2.31.0',
    description: 'requests 2.31.0 前在通过代理时可能错误转发 Proxy-Authorization 头，导致凭据泄露给目标服务器。',
    recommendation: '升级 requests 到 2.31.0 或更高版本。',
  },
  {
    ecosystem: 'pypi', package: 'flask', cve: 'CVE-2023-30861', severity: 'high', cwe: 'CWE-200',
    title: 'Flask 会话 Cookie 泄露', range: '<2.3.2', fixed: '2.3.2',
    description: 'Flask 2.3.2 前在特定缓存配置下可能向客户端返回其他用户会话的缓存响应。',
    recommendation: '升级 Flask 到 2.3.2 或更高版本。',
  },
  {
    ecosystem: 'pypi', package: 'pyyaml', cve: 'CVE-2020-14343', severity: 'critical', cwe: 'CWE-502',
    title: 'PyYAML 反序列化远程代码执行', range: '<5.4', fixed: '5.4',
    description: 'PyYAML 5.4 前 yaml.load 默认使用不安全的 Loader，可反序列化任意对象导致 RCE。',
    recommendation: '升级 PyYAML 到 5.4 或更高版本，并始终使用 yaml.safe_load。',
  },
  {
    ecosystem: 'pypi', package: 'jinja2', cve: 'CVE-2024-34064', severity: 'medium', cwe: 'CWE-79',
    title: 'Jinja2 属性注入（XSS）', range: '<3.1.4', fixed: '3.1.4',
    description: 'Jinja2 3.1.4 前 xmlattr 过滤器对键中的特殊字符处理不当，可注入属性导致 XSS。',
    recommendation: '升级 Jinja2 到 3.1.4 或更高版本。',
  },
  {
    ecosystem: 'pypi', package: 'urllib3', cve: 'CVE-2023-43804', severity: 'medium', cwe: 'CWE-200',
    title: 'urllib3 跨域 Cookie 头泄露', range: '<1.26.17', fixed: '1.26.17',
    description: 'urllib3 1.26.17 前在跟随重定向时可能将 Cookie 头转发到跨域目标。',
    recommendation: '升级 urllib3 到 1.26.17 或更高版本（注意 2.x 的兼容性）。',
  },
  // ---- Maven ----
  {
    ecosystem: 'maven', package: 'log4j-core', cve: 'CVE-2021-44228', severity: 'critical', cwe: 'CWE-502',
    title: 'Log4Shell 远程代码执行', range: '<2.17.0', fixed: '2.17.0',
    description: 'log4j-core 2.17.0 前存在 JNDI 注入（Log4Shell），可通过日志内容触发远程代码执行。',
    recommendation: '升级 log4j-core 到 2.17.0 或更高版本（Java 8 用 2.17.1）。',
  },
  {
    ecosystem: 'maven', package: 'spring-core', cve: 'CVE-2022-22965', severity: 'critical', cwe: 'CWE-94',
    title: 'Spring4Shell 远程代码执行', range: '<5.3.18', fixed: '5.3.18',
    description: 'spring-core 5.3.18 前在特定部署条件下存在数据绑定导致的远程代码执行（Spring4Shell）。',
    recommendation: '升级 Spring Framework 到 5.3.18 / 5.2.20 或更高版本。',
  },
  {
    ecosystem: 'maven', package: 'commons-collections', cve: 'CVE-2015-6420', severity: 'critical', cwe: 'CWE-502',
    title: 'commons-collections 反序列化 RCE', range: '<3.2.2', fixed: '3.2.2',
    description: 'commons-collections 3.2.2 前的 InvokerTransformer 等 gadget 可被反序列化利用导致 RCE。',
    recommendation: '升级 commons-collections 到 3.2.2 或更高版本。',
  },
  {
    ecosystem: 'maven', package: 'jackson-databind', cve: 'CVE-2020-36518', severity: 'high', cwe: 'CWE-787',
    title: 'jackson-databind 深嵌套 DoS', range: '<2.12.6', fixed: '2.12.6',
    description: 'jackson-databind 2.12.6 前对深层嵌套 JSON 处理可导致堆溢出/DoS。',
    recommendation: '升级 jackson-databind 到 2.12.6 或更高版本，并关闭 defaultTyping。',
  },
  // ---- Go ----
  {
    ecosystem: 'go', package: 'golang.org/x/text', cve: 'CVE-2021-38561', severity: 'high', cwe: 'CWE-125',
    title: 'golang.org/x/text 越界读', range: '<0.3.7', fixed: '0.3.7',
    description: 'golang.org/x/text 0.3.7 前在特定语言解析时存在越界读，可致崩溃。',
    recommendation: '升级 golang.org/x/text 到 0.3.7 或更高版本。',
  },
  {
    ecosystem: 'go', package: 'github.com/gin-gonic/gin', cve: 'CVE-2023-29401', severity: 'medium', cwe: 'CWE-116',
    title: 'Gin 文件名注入', range: '<1.9.1', fixed: '1.9.1',
    description: 'gin 1.9.1 前 c.FileAttachment 未完全转义文件名中的特殊字符。',
    recommendation: '升级 gin 到 1.9.1 或更高版本。',
  },
]

/** Manifests we know how to read, in priority order (lockfiles first). */
const MANIFESTS = [
  'package-lock.json',
  'package.json',
  'pnpm-lock.yaml',
  'pom.xml',
  'go.mod',
  'requirements.txt',
]

/**
 * Compare two dotted version strings numerically. Returns -1/0/1. Handles
 * pre-release suffixes crudely (a suffix sorts below its release) so that
 * `1.2.3-beta` < `1.2.3`. Missing segments count as 0 (`1.2` == `1.2.0`).
 */
export function compareVersions(a, b) {
  const split = v => {
    const s = String(v ?? '').trim().replace(/^[\^~>=<\s]+/, '')
    // Tolerate an epoch-style or four-part version; keep leading numeric run.
    const m = s.match(/^(\d+(?:\.\d+)*)(.*)$/)
    if (!m) return { nums: [0], pre: s }
    return { nums: m[1].split('.').map(n => Number(n) || 0), pre: m[2] || '' }
  }
  const pa = split(a)
  const pb = split(b)
  const len = Math.max(pa.nums.length, pb.nums.length)
  for (let i = 0; i < len; i++) {
    const na = pa.nums[i] ?? 0
    const nb = pb.nums[i] ?? 0
    if (na < nb) return -1
    if (na > nb) return 1
  }
  // Numerically equal: a pre-release suffix sorts lower than a clean release.
  if (pa.pre && !pb.pre) return -1
  if (!pa.pre && pb.pre) return 1
  return 0
}

/** Does `version` satisfy every clause in `range` (space-separated AND)? */
export function satisfiesRange(version, range) {
  const clauses = String(range ?? '').trim().split(/\s+/).filter(Boolean)
  if (!clauses.length) return false
  for (const clause of clauses) {
    const m = clause.match(/^(<=|>=|<|>|=)?\s*(.+)$/)
    if (!m) continue
    const op = m[1] || '='
    const target = m[2]
    const cmp = compareVersions(version, target)
    const ok = op === '<' ? cmp < 0
      : op === '<=' ? cmp <= 0
        : op === '>' ? cmp > 0
          : op === '>=' ? cmp >= 0
            : cmp === 0
    if (!ok) return false
  }
  return true
}

/** Strip common npm range operators to the concrete base version. */
function normalizeManifestVersion(raw) {
  if (raw === undefined || raw === null) return null
  let v = String(raw).trim()
  // "npm:foo@^1.2.3", "file:..", "git+https://..." carry no usable version.
  if (/^(file:|link:|git|https?:|workspace:|npm:)/i.test(v)) {
    const at = v.lastIndexOf('@')
    if (/^npm:/i.test(v) && at > 0) v = v.slice(at + 1)
    else return null
  }
  v = v.replace(/^[\^~>=<\s]+/, '').split(/\s+/)[0]
  if (!/^\d/.test(v)) return null
  return v
}

/** Read a file, returning '' when missing/unreadable.
 *  `asyncReadOverride` (set only during `parseManifestsAsync`) lets the async
 *  loader's already-read contents be reused so parsing needs no second read. */
let asyncReadOverride = null
function readMaybe(file) {
  if (asyncReadOverride && asyncReadOverride.has(file)) return asyncReadOverride.get(file)
  try {
    return readFileSync(file, 'utf8')
  } catch {
    return ''
  }
}

/** Collect {package, version} pairs from a package-lock.json (v1/v2/v3). */
function parsePackageLock(repoPath) {
  const deps = []
  const text = readMaybe(join(repoPath, 'package-lock.json'))
  if (!text) return deps
  let data
  try {
    data = JSON.parse(text)
  } catch {
    return deps
  }
  // lockfileVersion 2/3: "packages" keyed by node_modules path.
  if (data.packages && typeof data.packages === 'object') {
    for (const [key, info] of Object.entries(data.packages)) {
      if (!key || !info || typeof info !== 'object') continue
      // Local workspace links carry no published version to match.
      if (info.link) continue
      const name = info.name || key.replace(/^.*node_modules\//, '')
      if (!name || !info.version) continue
      deps.push({ package: name, version: String(info.version), dev: Boolean(info.dev) })
    }
  }
  // lockfileVersion 1: nested "dependencies".
  if (data.dependencies && typeof data.dependencies === 'object') {
    const walk = map => {
      for (const [name, info] of Object.entries(map)) {
        if (!info || typeof info !== 'object') continue
        if (info.version) deps.push({ package: name, version: String(info.version), dev: Boolean(info.dev) })
        if (info.dependencies) walk(info.dependencies)
      }
    }
    walk(data.dependencies)
  }
  return dedupeDeps(deps)
}

/** Collect declared {package, version} from package.json (fallback when no lock). */
function parsePackageJson(repoPath) {
  const deps = []
  const text = readMaybe(join(repoPath, 'package.json'))
  if (!text) return deps
  let data
  try {
    data = JSON.parse(text)
  } catch {
    return deps
  }
  for (const field of ['dependencies', 'devDependencies']) {
    const map = data[field]
    if (!map || typeof map !== 'object') continue
    for (const [name, raw] of Object.entries(map)) {
      const version = normalizeManifestVersion(raw)
      if (version) deps.push({ package: name, version, dev: field === 'devDependencies' })
    }
  }
  return dedupeDeps(deps)
}

/** Parse requirements.txt pins (name==version, name>=version, name). */
function parseRequirements(repoPath) {
  const deps = []
  const text = readMaybe(join(repoPath, 'requirements.txt'))
  if (!text) return deps
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#') || line.startsWith('-')) continue
    // name[extras] (==|>=|<=|~=) version
    const m = line.match(/^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(===|==|>=|<=|~=|>|<)?\s*([0-9][^\s;#]*)?/)
    if (!m) continue
    const name = m[1]
    const version = m[3] ? normalizeManifestVersion(m[3]) : null
    if (version) deps.push({ package: name, version, dev: false })
  }
  return dedupeDeps(deps)
}

/** Parse pom.xml <dependency> blocks (groupId/artifactId/version). */
function parsePom(repoPath) {
  const deps = []
  const text = readMaybe(join(repoPath, 'pom.xml'))
  if (!text) return deps
  const blockRe = /<dependency>([\s\S]*?)<\/dependency>/gi
  let m
  while ((m = blockRe.exec(text)) !== null) {
    const block = m[1]
    const artifact = (block.match(/<artifactId>\s*([^<]+?)\s*<\/artifactId>/i) || [])[1]
    const version = (block.match(/<version>\s*([^<]+?)\s*<\/version>/i) || [])[1]
    if (!artifact || !version) continue
    // Skip property placeholders like ${spring.version} — we cannot resolve them offline.
    if (/\$\{/.test(version)) continue
    const v = normalizeManifestVersion(version)
    if (v) deps.push({ package: artifact.trim(), version: v, dev: false })
  }
  return dedupeDeps(deps)
}

/** Parse go.mod require blocks/lines. */
function parseGoMod(repoPath) {
  const deps = []
  const text = readMaybe(join(repoPath, 'go.mod'))
  if (!text) return deps
  const lines = text.split(/\r?\n/)
  let inBlock = false
  for (const rawLine of lines) {
    const line = rawLine.trim()
    if (!line || line.startsWith('//')) continue
    if (/^require\s*\($/.test(line)) { inBlock = true; continue }
    if (inBlock && line === ')') { inBlock = false; continue }
    let body = null
    if (inBlock) body = line
    else if (/^require\s+/.test(line)) body = line.replace(/^require\s+/, '')
    if (!body) continue
    const m = body.match(/^(\S+)\s+v?([0-9][^\s]*)/)
    if (!m) continue
    const v = normalizeManifestVersion(m[2])
    if (v) deps.push({ package: m[1], version: v, dev: false })
  }
  return dedupeDeps(deps)
}

/** Deduplicate by package+version, preferring non-dev entries. */
function dedupeDeps(deps) {
  const seen = new Map()
  for (const dep of deps) {
    const key = `${dep.package}@${dep.version}`
    const prev = seen.get(key)
    if (!prev || (prev.dev && !dep.dev)) seen.set(key, dep)
  }
  return [...seen.values()]
}

/**
 * Parse every manifest found under repoPath (root only — most projects keep the
 * primary manifest at the root). Returns { deps: [{package,version,dev,manifest}],
 * manifests: [filenames found] }.
 */
export function parseManifests(repoPath) {
  const manifests = []
  const deps = []
  const push = (list, manifest) => {
    if (list.length) manifests.push(manifest)
    for (const dep of list) deps.push({ ...dep, manifest })
  }
  for (const name of MANIFESTS) {
    if (!existsSync(join(repoPath, name))) continue
    if (name === 'package-lock.json') push(parsePackageLock(repoPath), name)
    else if (name === 'package.json') push(parsePackageJson(repoPath), name)
    else if (name === 'requirements.txt') push(parseRequirements(repoPath), name)
    else if (name === 'pom.xml') push(parsePom(repoPath), name)
    else if (name === 'go.mod') push(parseGoMod(repoPath), name)
  }
  // package-lock + package.json both list the same npm deps; dedupe globally by
  // package@version, keeping the first manifest that contributed it.
  return { deps: dedupeDeps(deps), manifests: [...new Set(manifests)] }
}

/**
 * Match parsed dependencies against the advisory DB. Returns an array of
 * findings shaped like submitFinding inputs (plus manifest/file_path). Each
 * contains every advisory that applies for that dependency.
 */
export function matchVulnerabilities(deps) {
  const out = []
  for (const dep of deps ?? []) {
    const pkg = String(dep.package ?? '').toLowerCase()
    if (!pkg) continue
    for (const adv of VULN_DB) {
      if (adv.package.toLowerCase() !== pkg) continue
      // Only compare within the same ecosystem family when both are known.
      if (dep.ecosystem && adv.ecosystem && dep.ecosystem !== adv.ecosystem) continue
      if (!satisfiesRange(dep.version, adv.range)) continue
      out.push({
        ecosystem: adv.ecosystem,
        package: dep.package,
        version: dep.version,
        manifest: dep.manifest,
        file_path: dep.manifest,
        cve: adv.cve,
        severity: adv.severity,
        cwe: adv.cwe,
        title: `依赖组件已知漏洞：${dep.package}@${dep.version}（${adv.cve}）`,
        description: `${adv.description}\n受影响版本：${adv.range}；修复版本：${adv.fixed}。当前声明版本：${dep.version}。`,
        evidence: `${dep.manifest} 中声明 ${dep.package}@${dep.version}，命中 ${adv.cve}（${adv.title}）。`,
        recommendation: adv.recommendation,
      })
    }
  }
  // Highest severity first, then package name for stable ordering.
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  return out.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9) || a.package.localeCompare(b.package))
}

/**
 * Top-level entry: parse manifests, match advisories. Returns
 * { vulns, manifests, depCount }. Never throws — parse/match errors degrade to
 * an empty result so SCA can never block an audit run.
 */
export function scanDependencies(repoPath) {
  try {
    const { deps, manifests } = parseManifests(repoPath)
    const vulns = matchVulnerabilities(deps)
    return { vulns, manifests, depCount: deps.length }
  } catch {
    return { vulns: [], manifests: [], depCount: 0 }
  }
}

/**
 * Async twin of `parseManifests`: reads the detected manifests with
 * `fs.promises` (so large lockfiles do not occupy the event loop), then hands
 * the parsed text to the same per-format parsers by stubbing the sync reader.
 * Produces identical output to the sync path.
 */
export async function parseManifestsAsync(repoPath) {
  const texts = new Map()
  for (const name of MANIFESTS) {
    const full = join(repoPath, name)
    try {
      texts.set(full, await readFile(full, 'utf8'))
    } catch { /* missing / unreadable */ }
    // Yield between manifests so HTTP/session work interleaves with the scan.
    await new Promise(resolve => setImmediate(resolve))
  }
  // The per-format parsers call `readMaybe`, which consults this override map
  // first so the async loader's already-read contents are reused without a
  // second synchronous read.
  asyncReadOverride = texts
  try {
    return parseManifests(repoPath)
  } finally {
    asyncReadOverride = null
  }
}

/**
 * Async mirror of `scanDependencies`. Reads manifests with `fs.promises` and
 * yields so a run start does not block the DSH host while manifests load.
 * Same result shape; never throws.
 */
export async function scanDependenciesAsync(repoPath) {
  try {
    const { deps, manifests } = await parseManifestsAsync(repoPath)
    const vulns = matchVulnerabilities(deps)
    return { vulns, manifests, depCount: deps.length }
  } catch {
    return { vulns: [], manifests: [], depCount: 0 }
  }
}

/**
 * Render SCA results as a prompt section. These are *deterministic* version
 * matches (not model judgment), so the framing asks the agent to (a) report
 * them directly as findings via the normal tool, and (b) additionally assess
 * reachability — whether the vulnerable API is actually used with untrusted
 * input, which decides severity in context.
 */
export function formatScaSection(scan) {
  const vulns = scan?.vulns ?? []
  if (!vulns.length) return ''
  const lines = [
    '# 第三方依赖已知漏洞（SCA 自动匹配）',
    '',
    `以下是插件解析依赖清单（${(scan.manifests ?? []).join('、')}）后，对照内置漏洞库自动匹配到的已知漏洞。`,
    '这些是**确定性版本匹配**（不是猜测）：只要组件版本命中，就应当作为漏洞上报。',
    '请对每一条：① 用 `code_audit_submit_finding` 直接上报（category 填「依赖漏洞」，cwe_id 填给出的 CWE，confidence 填 high）；',
    '② 进一步查看该依赖相关 API 是否真的在代码中被使用、入参是否可被外部控制——如可被利用，在 evidence 中补充实际调用点，severity 可据此上调。',
    '',
    '| # | 组件 | 版本 | CVE | 严重度 | CWE | 修复版本提示 |',
    '| --- | --- | --- | --- | --- | --- | --- |',
  ]
  vulns.forEach((v, index) => {
    const fix = String(v.recommendation || '').replaceAll('|', '\\|')
    lines.push(`| ${index + 1} | ${v.package} | ${v.version} | ${v.cve} | ${v.severity} | ${v.cwe} | ${fix} |`)
  })
  lines.push('', '（依赖漏洞与源码漏洞一起计入报告；如果核对后确认该漏洞在当前代码中不可达，可在 description 中说明上下文风险较低，但仍需上报。）')
  return lines.join('\n')
}

export { VULN_DB }
