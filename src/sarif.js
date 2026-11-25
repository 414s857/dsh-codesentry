import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const { version: TOOL_VERSION } = require('../package.json')

const TOOL_NAME = 'dsh-codesentry'
const TOOL_URI = 'https://github.com/414s857/dsh-codesentry'

// SARIF levels: critical/high fail the gate, medium warns, low notes, info is informational.
const SEVERITY_LEVELS = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'none',
}

function slugify(value) {
  const slug = String(value ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
  return slug || ''
}

function cweHelpUri(cweId) {
  const match = /^CWE-(\d+)$/i.exec(String(cweId ?? '').trim())
  return match ? `https://cwe.mitre.org/data/definitions/${match[1]}.html` : undefined
}

function ruleIdFor(finding) {
  const cwe = String(finding.cwe_id ?? '').trim().toUpperCase()
  if (/^CWE-\d+$/.test(cwe)) return cwe
  const slug = slugify(finding.category)
  return slug ? `dsh-${slug}` : 'dsh-finding'
}

function ruleNameFor(finding) {
  const slug = slugify(finding.category)
  return slug || slugify(finding.title) || 'Finding'
}

function findingMessage(finding) {
  const parts = [String(finding.title ?? '')]
  const description = String(finding.description ?? '').replace(/\s+/g, ' ').trim()
  if (description) parts.push(description.length > 400 ? `${description.slice(0, 400)}…` : description)
  const evidence = String(finding.evidence ?? '').replace(/\s+/g, ' ').trim()
  if (evidence) parts.push(`触发路径：${evidence.length > 300 ? `${evidence.slice(0, 300)}…` : evidence}`)
  return parts.join(' — ')
}

/**
 * Convert a task's findings into a SARIF 2.1.0 run so standard scanners and
 * CI gates (GitHub code scanning, VS Code SARIF viewer) can consume them.
 * Findings already carry verified file paths/line ranges (verify.js) — no
 * synthetic locations are produced here.
 */
export function buildSarifReport(task, findings) {
  const rules = []
  const ruleIndexById = new Map()
  const results = []

  const ordered = [...findings].sort((left, right) => {
    const idDelta = ruleIdFor(left).localeCompare(ruleIdFor(right))
    if (idDelta !== 0) return idDelta
    return String(left.created_at ?? '').localeCompare(String(right.created_at ?? ''))
  })

  for (const finding of ordered) {
    const ruleId = ruleIdFor(finding)
    if (!ruleIndexById.has(ruleId)) {
      const helpUri = cweHelpUri(finding.cwe_id)
      const rule = {
        id: ruleId,
        name: ruleNameFor(finding),
        shortDescription: { text: finding.category || finding.title || ruleId },
      }
      if (helpUri) rule.helpUri = helpUri
      rule.defaultConfiguration = { level: SEVERITY_LEVELS[finding.severity] ?? 'warning' }
      ruleIndexById.set(ruleId, rules.length)
      rules.push(rule)
    }

    const startLine = Number(finding.line_start)
    const endLine = Number(finding.line_end ?? finding.line_start)
    const region = Number.isFinite(startLine) && startLine > 0
      ? {
          startLine,
          ...(Number.isFinite(endLine) && endLine >= startLine ? { endLine } : {}),
        }
      : undefined

    const properties = {
      title: finding.title ?? '',
      severity: finding.severity,
      category: finding.category ?? '',
      confidence: finding.confidence || 'medium',
      status: finding.status,
      'dsh-finding-id': finding.id,
      'dsh-run-id': finding.run_id ?? '',
    }

    const result = {
      ruleId,
      ruleIndex: ruleIndexById.get(ruleId),
      level: SEVERITY_LEVELS[finding.severity] ?? 'warning',
      message: { text: findingMessage(finding) },
      locations: [{
        physicalLocation: {
          artifactLocation: {
            uri: String(finding.file_path ?? '').replaceAll('\\', '/'),
            uriBaseId: '%SRCROOT%',
          },
          ...(region ? { region } : {}),
        },
      }],
      partialFingerprints: { 'dshFingerprint/v1': String(finding.fingerprint ?? '') },
      properties,
    }
    results.push(result)
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: TOOL_NAME,
          version: TOOL_VERSION,
          informationUri: TOOL_URI,
          rules,
        },
      },
      originalUriBaseIds: {
        '%SRCROOT%': { description: { text: '仓库根目录（任务审计目录）' } },
      },
      automationDetails: {
        description: { text: `dsh-codesentry 任务 ${task?.name ?? task?.id ?? ''}` },
      },
      results,
    }],
  }
}
