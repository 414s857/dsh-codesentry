import { statSync, readFileSync } from 'node:fs'
import { join, resolve, sep } from 'node:path'

/**
 * Finding evidence verification — problem #3 from the issue list: the audit
 * agent can hallucinate file paths, line numbers, and code snippets, and the
 * old submitFinding stored whatever it received. Every finding now goes
 * through this verifier before it touches the database; a failed check comes
 * back to the agent (via the tool-error channel) as concrete, actionable
 * problems so the model can re-report with real evidence.
 */

// Upper bound on the evidence file we are willing to read. Findings pointing
// at giant generated/data files skip the deep snippet check but stay valid.
const MAX_FILE_BYTES = 2 * 1024 * 1024

// Tolerance for line numbers: the model's anchors may drift a line or two,
// but a start line beyond this is treated as out of range.
const LINE_TOLERANCE = 3

// A snippet line shorter than this is noise (`}`, `);`, `end`) and is ignored
// when deciding whether a partially-matched snippet is real.
const MIN_SUBSTANTIVE_LINE = 4

// Fraction of substantive snippet lines that must exist somewhere in the file
// for a snippet to still count as real evidence when contiguous matching fails.
const PARTIAL_MATCH_RATIO = 0.8

/** Full-width punctuation/letters → half-width, so CJK-authored snippets match. */
function toHalfWidth(text) {
  let out = ''
  for (const ch of text) {
    const code = ch.codePointAt(0)
    if (code === 0x3000) out += ' '
    else if (code >= 0xff01 && code <= 0xff5e) out += String.fromCodePoint(code - 0xfee0)
    else out += ch
  }
  return out
}

/**
 * Normalise text for fuzzy-but-strict comparison: full-width → half-width,
 * collapse whitespace, strip quote characters, lowercase. CRLF, indentation
 * and quote-style differences are tolerated; content differences are not.
 */
function normaliseText(value) {
  return toHalfWidth(String(value ?? ''))
    .replace(/\s+/g, ' ')
    .replace(/["'`]/g, '')
    .trim()
    .toLowerCase()
}

/** Same path normalisation the runner applies before storing findings. */
export function normaliseRelativePath(value) {
  return String(value ?? '')
    .replaceAll('\\', '/')
    .replace(/^\.\//, '')
    .replace(/^\/+/, '')
    .trim()
}

/**
 * Verify that a finding's evidence actually exists in the repository.
 * Returns { ok, problems, actualLineStart, actualLineEnd, corrected } —
 * `problems` lists Chinese, agent-readable reasons for rejection;
 * `actualLineStart/End` carry the snippet-located lines when the model's
 * numbers drifted (the runner stores the corrected values).
 */
export function verifyFindingEvidence({ repoPath, filePath, lineStart, lineEnd, snippet, allowedFiles }) {
  const problems = []
  const path = normaliseRelativePath(filePath)
  let actualLineStart
  let actualLineEnd
  let corrected = false

  if (!path) {
    problems.push('file_path 为空，必须提供仓库内的相对路径')
    return { ok: false, problems, actualLineStart, actualLineEnd, corrected }
  }

  // Shard scope: the finding must land inside the shard being audited.
  if (allowedFiles && !allowedFiles.has(path)) {
    problems.push(`file_path "${path}" 不在当前切片的文件清单内（跨切片问题请留到汇总阶段上报）`)
  }

  // Path traversal: the resolved file must stay inside the repository.
  const repoRoot = resolve(repoPath)
  const absolute = resolve(repoRoot, path)
  if (absolute !== repoRoot && !absolute.startsWith(repoRoot + sep)) {
    problems.push(`file_path "${path}" 越出了仓库目录`)
    return { ok: false, problems, actualLineStart, actualLineEnd, corrected }
  }

  let stat
  try {
    stat = statSync(absolute)
  } catch {
    problems.push(`file_path "${path}" 在仓库中不存在（相对 ${repoPath}）`)
    return { ok: false, problems, actualLineStart, actualLineEnd, corrected }
  }
  if (!stat.isFile()) {
    problems.push(`file_path "${path}" 不是文件（可能是目录）`)
    return { ok: false, problems, actualLineStart, actualLineEnd, corrected }
  }
  if (stat.size > MAX_FILE_BYTES) {
    // Too large to verify cheaply — path and shard scope already checked.
    return { ok: problems.length === 0, problems, actualLineStart, actualLineEnd, corrected }
  }

  let content
  try {
    content = readFileSync(absolute, 'utf8')
  } catch {
    return { ok: problems.length === 0, problems, actualLineStart, actualLineEnd, corrected }
  }
  const lines = content.split(/\r?\n/)
  const lineCount = lines.length
  const normalisedLines = lines.map(normaliseText)

  const start = Number(lineStart)
  const end = Number.isFinite(Number(lineEnd)) ? Number(lineEnd) : start

  if (!Number.isFinite(start) || start < 1) {
    problems.push(`line_start "${lineStart}" 不是有效行号（应为 ≥ 1 的整数）`)
  } else if (start > lineCount + LINE_TOLERANCE) {
    problems.push(`line_start ${start} 超出文件行数（${path} 共 ${lineCount} 行）`)
  }

  const snippetText = String(snippet ?? '').trim()
  if (snippetText) {
    const rawSnippetLines = snippetText.split(/\r?\n/).map(normaliseText).filter(line => line.length > 0)
    const substantive = rawSnippetLines.filter(line => line.length >= MIN_SUBSTANTIVE_LINE)
    const target = normaliseText(snippetText)
    const span = Math.max(rawSnippetLines.length, 1)

    // Locate the snippet by its first substantive line, then require the
    // remaining lines to appear in order nearby. Greedy window-growing from
    // the claimed start matched far-away regions (a wide window spanning the
    // whole file trivially contains the target as a substring), so anchoring
    // on the first substantive line is the only reliable strategy.
    let anchorIndex = -1
    const firstSubstantive = substantive[0]
    if (firstSubstantive) {
      anchorIndex = normalisedLines.findIndex(fileLine => fileLine.includes(firstSubstantive))
    }

    let contiguous = false
    if (anchorIndex >= 0) {
      // Check that the rest of the substantive lines appear in order within
      // a reasonable window after the anchor (allow interleaved file lines).
      let cursor = anchorIndex
      let ordered = 1
      for (let s = 1; s < substantive.length; s++) {
        let found = -1
        for (let j = cursor + 1; j <= Math.min(cursor + 6 + substantive.length, lineCount); j++) {
          if (normalisedLines[j].includes(substantive[s])) { found = j; break }
        }
        if (found >= 0) { ordered++; cursor = found }
      }
      contiguous = ordered === substantive.length
      if (contiguous) {
        const foundStart = anchorIndex + 1
        const foundEnd = anchorIndex + Math.max(span, cursor - anchorIndex + 1)
        if (Number.isFinite(start) && start >= 1 && Math.abs(start - foundStart) > LINE_TOLERANCE) {
          actualLineStart = foundStart
          actualLineEnd = foundEnd
          corrected = true
        }
      }
    }

    if (!contiguous) {
      // Partial match: a large share of substantive lines must still exist
      // somewhere (reordering / edits tolerated), otherwise it is fabricated.
      let foundCount = 0
      const missing = []
      for (const line of substantive) {
        const exists = normalisedLines.some(fileLine => fileLine.includes(line))
        if (exists) foundCount++
        else if (missing.length < 3) missing.push(line.slice(0, 60))
      }
      const ratio = substantive.length ? foundCount / substantive.length : 1
      if (substantive.length && ratio < PARTIAL_MATCH_RATIO) {
        problems.push(
          `code_snippet 与 ${path} 的内容不符（${substantive.length} 行实质代码中仅 ${foundCount} 行能在文件中找到）` +
          (missing.length ? `，找不到的行如："${missing.join('", "')}"` : '') +
          '，请上报文件中真实存在的代码',
        )
      }
    }
  }

  return { ok: problems.length === 0, problems, actualLineStart, actualLineEnd, corrected }
}

/** Format verification problems as the error message thrown back to the agent. */
export function formatEvidenceProblems(problems) {
  return `漏洞证据校验未通过，已拒收。请核对以下问题后用真实证据重新上报：\n- ${problems.join('\n- ')}`
}
