import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { verifyFindingEvidence, formatEvidenceProblems, normaliseRelativePath } from '../src/verify.js'

/** Build a throwaway repo with one file and return { root, cleanup }. */
function repoWith(rel, contents) {
  const root = mkdtempSync(join(tmpdir(), 'audit-verify-'))
  const full = join(root, rel)
  mkdirSync(join(full, '..'), { recursive: true })
  writeFileSync(full, contents)
  return { root, cleanup: () => rmSync(root, { recursive: true, force: true }) }
}

const SAMPLE = [
  'const express = require("express")',
  'const app = express()',
  'app.get("/user", (req, res) => {',
  '  const id = req.query.id',
  '  db.query("SELECT * FROM users WHERE id = " + id)',
  '  res.send(rows)',
  '})',
].join('\n')

test('normaliseRelativePath strips ./ and leading slashes and converts backslashes', () => {
  assert.equal(normaliseRelativePath('.\\src\\a.js'), 'src/a.js')
  assert.equal(normaliseRelativePath('./src/a.js'), 'src/a.js')
  assert.equal(normaliseRelativePath('/src/a.js'), 'src/a.js')
  assert.equal(normaliseRelativePath('src/a.js'), 'src/a.js')
})

test('accepts a finding whose exact snippet exists', () => {
  const { root, cleanup } = repoWith('app.js', SAMPLE)
  try {
    const r = verifyFindingEvidence({
      repoPath: root,
      filePath: 'app.js',
      lineStart: 5,
      lineEnd: 5,
      snippet: 'db.query("SELECT * FROM users WHERE id = " + id)',
    })
    assert.equal(r.ok, true, JSON.stringify(r.problems))
    assert.equal(r.corrected, false)
  } finally {
    cleanup()
  }
})

test('tolerates small line-number drift and reports corrected line', () => {
  const { root, cleanup } = repoWith('app.js', SAMPLE)
  try {
    const r = verifyFindingEvidence({
      repoPath: root,
      filePath: 'app.js',
      lineStart: 1, // actual snippet starts at line 5
      lineEnd: 1,
      snippet: 'db.query("SELECT * FROM users WHERE id = " + id)',
    })
    assert.equal(r.ok, true, JSON.stringify(r.problems))
    assert.equal(r.corrected, true)
    assert.equal(r.actualLineStart, 5)
  } finally {
    cleanup()
  }
})

test('rejects a fabricated snippet that is not in the file', () => {
  const { root, cleanup } = repoWith('app.js', SAMPLE)
  try {
    const r = verifyFindingEvidence({
      repoPath: root,
      filePath: 'app.js',
      lineStart: 3,
      lineEnd: 3,
      snippet: 'exec("rm -rf /") // totally fabricated line here',
    })
    assert.equal(r.ok, false)
    assert.ok(r.problems.some(p => p.includes('不符')), JSON.stringify(r.problems))
  } finally {
    cleanup()
  }
})

test('rejects a missing file', () => {
  const { root, cleanup } = repoWith('app.js', SAMPLE)
  try {
    const r = verifyFindingEvidence({ repoPath: root, filePath: 'nope.js', lineStart: 1, lineEnd: 1, snippet: 'x' })
    assert.equal(r.ok, false)
    assert.ok(r.problems.some(p => p.includes('不存在')))
  } finally {
    cleanup()
  }
})

test('rejects path traversal outside the repo', () => {
  const { root, cleanup } = repoWith('app.js', SAMPLE)
  try {
    const r = verifyFindingEvidence({ repoPath: root, filePath: '../../etc/passwd', lineStart: 1, lineEnd: 1, snippet: 'root' })
    assert.equal(r.ok, false)
    assert.ok(r.problems.some(p => p.includes('越出')), JSON.stringify(r.problems))
  } finally {
    cleanup()
  }
})

test('enforces shard scope via allowedFiles', () => {
  const { root, cleanup } = repoWith('app.js', SAMPLE)
  try {
    const r = verifyFindingEvidence({
      repoPath: root,
      filePath: 'app.js',
      lineStart: 5,
      lineEnd: 5,
      snippet: 'db.query("SELECT * FROM users WHERE id = " + id)',
      allowedFiles: new Set(['other.js']),
    })
    assert.equal(r.ok, false)
    assert.ok(r.problems.some(p => p.includes('不在当前切片')))
  } finally {
    cleanup()
  }
})

test('rejects an invalid / far-out line number', () => {
  const { root, cleanup } = repoWith('app.js', SAMPLE)
  try {
    const r = verifyFindingEvidence({
      repoPath: root,
      filePath: 'app.js',
      lineStart: 9999,
      lineEnd: 9999,
      snippet: 'db.query("SELECT * FROM users WHERE id = " + id)',
    })
    assert.equal(r.ok, false)
    assert.ok(r.problems.some(p => p.includes('超出文件行数')))
  } finally {
    cleanup()
  }
})

test('normalises full-width CJK punctuation when matching snippets', () => {
  const { root, cleanup } = repoWith('cn.js', 'const msg = "错误（致命）"\nfoo()\n')
  try {
    // Query uses half-width parens; file uses full-width; both should match.
    const r = verifyFindingEvidence({
      repoPath: root,
      filePath: 'cn.js',
      lineStart: 1,
      lineEnd: 1,
      snippet: 'const msg = "错误(致命)"',
    })
    assert.equal(r.ok, true, JSON.stringify(r.problems))
  } finally {
    cleanup()
  }
})

test('empty snippet relies on path/existence checks only', () => {
  const { root, cleanup } = repoWith('app.js', SAMPLE)
  try {
    const r = verifyFindingEvidence({ repoPath: root, filePath: 'app.js', lineStart: 1, lineEnd: 1, snippet: '' })
    assert.equal(r.ok, true, JSON.stringify(r.problems))
  } finally {
    cleanup()
  }
})

test('formatEvidenceProblems renders a readable message', () => {
  const msg = formatEvidenceProblems(['问题一', '问题二'])
  assert.ok(msg.includes('问题一'))
  assert.ok(msg.includes('问题二'))
  assert.ok(msg.includes('证据校验未通过'))
})
