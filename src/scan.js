import { readFileSync } from 'node:fs'
import { readFile } from 'node:fs/promises'

/**
 * Lightweight static-analysis pre-pass (problem #2): regex-based security
 * signals fed into the audit prompts as *leads*, not conclusions. The goal is
 * recall — grep catches what a model skimming a file list misses; precision
 * stays the audit agent's job, and every signal says so explicitly.
 *
 * Pure functions only: no walking (the shard plan already lists files), no
 * AST, no dependencies. Files are capped by sharding's MAX_FILE_BYTES, so
 * scanning is cheap; per-signal hit caps keep a noisy rule from flooding a
 * prompt.
 */

/** Individual signals embedded in one prompt are capped per rule and overall. */
const MAX_HITS_PER_RULE = 8
const MAX_TOTAL_SIGNALS = 60
/** Max characters of the matched line shown as excerpt. */
const EXCERPT_MAX = 160

/**
 * Rule table. `pattern` matches one line (case-insensitive unless the rule
 * says otherwise); `skip` suppresses common false-positive shapes (comments,
 * test files, declarations without use). `hint` is written to the agent and
 * must state what to check, never a verdict.
 */
const RULES = [
  {
    id: 'sql-concat',
    name: 'SQL 语句拼接',
    severity: 'high',
    pattern: /(?:select|insert\s+into|update|delete\s+from)\b[^;\n]{0,200}?(?:\+\s*\w|\$\{|\+\s*['"`]|%\s*\(|format\(|f['"`]\s*\.\s*exec|\bexecute\()/i,
    hint: '确认 SQL 语句是否拼接了用户可控输入，是否存在参数化查询可用',
  },
  {
    id: 'sql-exec-concat',
    name: '动态 SQL 执行',
    severity: 'high',
    pattern: /\b(?:exec(?:ute)?\s*\(\s*|query\(\s*)(?:['"`][^'"`]*['"`]\s*\+|\$\{|`[^`]*\$\{)/i,
    hint: '确认执行层是否直接拼接 SQL 字符串，参数是否经过白名单/参数化',
  },
  {
    id: 'eval-use',
    name: 'eval/exec 动态执行',
    severity: 'high',
    pattern: /\b(?:eval\s*\(|exec\s*\(|new\s+Function\s*\()/,
    skip: /\b(?:this\.exec|\.exec\s*\(\s*(?:re|regex|pattern|match)\b)/,
    hint: '确认 eval/exec 的输入是否用户可控，能否改为白名单或直接调用',
  },
  {
    id: 'command-injection',
    name: '命令执行拼接',
    severity: 'critical',
    pattern: /(?:child_process|execSync|spawnSync|os\.system|subprocess|shell=True|\bexecve?\b).{0,120}?(?:\+\s*\w+|\$\{|`)/i,
    hint: '确认命令参数是否含用户输入，是否使用数组形式传参并过滤元字符',
  },
  {
    id: 'deserialization',
    name: '反序列化风险',
    severity: 'high',
    pattern: /\b(?:pickle\.loads?|yaml\.load\s*\((?![^)]*Loader)|unserialize|ObjectInputStream|readObject\s*\(|marshal\.loads?|php:\/\/input.*unserialize)/i,
    hint: '确认反序列化的数据来源是否可信，yaml.load 是否使用 SafeLoader',
  },
  {
    id: 'xss-html',
    name: 'XSS 注入点',
    severity: 'medium',
    pattern: /(?:innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)/,
    hint: '确认写入 HTML 的内容是否含用户输入，是否有转义/净化处理',
  },
  {
    id: 'hardcoded-secret',
    name: '疑似硬编码密钥',
    severity: 'high',
    pattern: /(?:api[_-]?key|secret|password|passwd|token|access[_-]?key|private[_-]?key)\s*[:=]\s*['"`][A-Za-z0-9+/_\-]{16,}['"`]/i,
    // Placeholder values like `examplexxxxxxxxxxxxxxxx` (a placeholder word
    // immediately followed by the required length) are skipped; separated
    // words (`example-key-123...`) still match, so real keys stay flagged.
    skip: /['"][A-Za-z0-9+/_\-]*(?:example|sample|placeholder|dummy|changeme|xxxx+)[A-Za-z0-9+/_\-]*['"]/i,
    hint: '确认是否为真实凭据写入源码；如为真实密钥需立即轮换并改用环境变量/密钥管理',
  },
  {
    id: 'weak-hash',
    name: '弱哈希算法',
    severity: 'medium',
    pattern: /\b(?:md5|sha1)\b(?!\s*\().{0,40}?(?:createHash|digest|hashlib|MessageDigest)|hashlib\.(?:md5|sha1)\(|createHash\(\s*['"`](?:md5|sha1)['"`]/i,
    hint: '确认用途：密码存储/签名/完整性校验不应使用 MD5/SHA1，建议 SHA-256 及以上或专用 KDF',
  },
  {
    id: 'weak-random',
    name: '弱随机数用于安全场景',
    severity: 'medium',
    pattern: /(?:Math\.random\s*\(\s*\)|random\.random\s*\(\s*\)|rand\s*\(\s*\)).{0,80}?(?:token|secret|nonce|salt|password|session|key|otp|verify)/i,
    hint: '确认随机数是否用于令牌/密钥等安全场景；应改用 crypto.getRandomValues/secrets 模块',
  },
  {
    id: 'ssrf-url',
    name: '用户可控 URL 请求',
    severity: 'high',
    pattern: /(?:fetch\s*\(|axios[.(]|requests\.(?:get|post)|urlopen|http\.Get|curl_init).{0,80}?(?:req\.(?:query|body|params)|request\.(?:query|body|params)|\bargs\b|\bparams\b)/i,
    hint: '确认请求目标是否可被用户控制指向内网地址；需要域名/协议白名单',
  },
  {
    id: 'path-traversal',
    name: '路径拼接读文件',
    severity: 'medium',
    pattern: /(?:readFile|readFileSync|open\s*\(|sendFile|createReadStream|fs\.read).{0,60}?(?:\+\s*(?:req|request|params|query|user)|\$\{\s*(?:req|request|params|query|user))/i,
    hint: '确认文件路径是否含用户输入，是否有目录穿越防护（规范化+白名单前缀）',
  },
  {
    id: 'debug-endpoint',
    name: '调试/管理接口暴露',
    severity: 'medium',
    pattern: /(?:app\.(?:get|post|use)\s*\(\s*['"`][^'"`]*(?:debug|admin|internal|exec|eval)|DEBUG\s*=\s*true|FLASK_ENV\s*=\s*['"]development)/i,
    hint: '确认调试端点是否会在生产暴露，是否有鉴权保护',
  },
]

/** Test/doc file shapes whose hits are almost always noise. */
const LOW_SIGNAL_PATH = /(?:^|\/)(?:test|tests|__tests__|spec|specs|mock|fixtures?|examples?|demos?|docs?)\/|\.test\.|\.spec\.|-test\.|_test\./i

function scanFileForSignals(filePath, content) {
  const signals = []
  const isLowSignalPath = LOW_SIGNAL_PATH.test(filePath)
  const lines = content.split(/\r?\n/)
  for (const rule of RULES) {
    let hits = 0
    for (let index = 0; index < lines.length && hits < MAX_HITS_PER_RULE; index++) {
      const line = lines[index]
      if (!line || line.length > 4000) continue
      if (rule.skip && rule.skip.test(line)) continue
      if (!rule.pattern.test(line)) continue
      // Comment-only lines are weak evidence; keep them only outside tests.
      if (/^\s*(?:\/\/|#|\*|\/\*)/.test(line) && isLowSignalPath) continue
      hits += 1
      signals.push({
        ruleId: rule.id,
        name: rule.name,
        severity: rule.severity,
        filePath,
        line: index + 1,
        excerpt: line.trim().slice(0, EXCERPT_MAX),
        hint: rule.hint,
        lowConfidence: isLowSignalPath,
      })
    }
  }
  return signals
}

/**
 * Scan the given files (paths relative to repoPath) for security signals.
 * Returns { signals, byFile } where byFile maps file path → signal count.
 * Missing/unreadable files are skipped silently; per-file and overall caps
 * bound the output size so prompts never flood.
 */
export function scanRepositorySignals(repoPath, files) {
  const signals = []
  const byFile = new Map()
  const pathList = Array.isArray(files)
    ? files.map(f => (typeof f === 'string' ? f : f?.path)).filter(Boolean)
    : []
  for (const relPath of pathList) {
    if (signals.length >= MAX_TOTAL_SIGNALS) break
    const cleanPath = String(relPath).replaceAll('\\', '/')
    let content
    try {
      content = readFileSync(`${repoPath}/${cleanPath}`, 'utf8')
    } catch {
      continue
    }
    const fileSignals = scanFileForSignals(cleanPath, content)
    if (fileSignals.length) {
      byFile.set(cleanPath, fileSignals.length)
      const room = MAX_TOTAL_SIGNALS - signals.length
      signals.push(...fileSignals.slice(0, room))
    }
  }
  return { signals, byFile }
}

/**
 * Async twin of `scanRepositorySignals`. Reads candidate files with
 * `fs.promises` and yields to the event loop periodically, so scanning a large
 * file list does not block the DSH host while a run is starting. Same output
 * shape as the sync version.
 */
export async function scanRepositorySignalsAsync(repoPath, files) {
  const signals = []
  const byFile = new Map()
  const pathList = Array.isArray(files)
    ? files.map(f => (typeof f === 'string' ? f : f?.path)).filter(Boolean)
    : []
  let sinceYield = 0
  for (const relPath of pathList) {
    if (signals.length >= MAX_TOTAL_SIGNALS) break
    // Yield every 32 files so a big shard's scan interleaves with HTTP/session work.
    if (++sinceYield >= 32) {
      sinceYield = 0
      await new Promise(resolve => setImmediate(resolve))
    }
    const cleanPath = String(relPath).replaceAll('\\', '/')
    let content
    try {
      content = await readFile(`${repoPath}/${cleanPath}`, 'utf8')
    } catch {
      continue
    }
    const fileSignals = scanFileForSignals(cleanPath, content)
    if (fileSignals.length) {
      byFile.set(cleanPath, fileSignals.length)
      const room = MAX_TOTAL_SIGNALS - signals.length
      signals.push(...fileSignals.slice(0, room))
    }
  }
  return { signals, byFile }
}

/**
 * Render signals as a prompt section. `signalsFor` is the array relevant to
 * the current shard; the framing stresses leads-not-verdicts so the agent
 * verifies before reporting.
 */
export function formatSignalsSection(signals) {
  if (!signals?.length) return ''
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  const sorted = [...signals].sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9) || a.filePath.localeCompare(b.filePath) || a.line - b.line)
  const lines = [
    '# 静态扫描线索',
    '',
    '以下是正则静态扫描给出的可疑位置，**只是线索不是结论**——其中相当一部分可能是误报。',
    '审计时请逐条打开对应位置核实：确认为真实问题的按正常流程上报漏洞；排除的无需上报，也不要直接照抄线索措辞。',
    '',
    '| # | 严重度 | 位置 | 代码行 | 检查要点 |',
    '| --- | --- | --- | --- | --- |',
  ]
  sorted.forEach((signal, index) => {
    const location = `${signal.filePath}:${signal.line}`.replaceAll('|', '\\|')
    const excerpt = signal.excerpt.replaceAll('|', '\\|')
    const confidence = signal.lowConfidence ? '（测试/示例文件，优先怀疑误报）' : ''
    lines.push(`| ${index + 1} | ${signal.severity}${confidence} | ${location} | \`${excerpt}\` | ${signal.hint} |`)
  })
  if (sorted.length >= MAX_TOTAL_SIGNALS) {
    lines.push('', `（线索过多，仅显示前 ${MAX_TOTAL_SIGNALS} 条；完整审计仍以文件清单为准，不要只盯线索）`)
  }
  return lines.join('\n')
}
