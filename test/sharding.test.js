import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { planShards, planShardsAsync, buildShardWorkspaceInfo, SHARD_STATUS_LABELS } from '../src/sharding.js'

/** Build a throwaway repo tree from a { relativePath: contents } map. */
function makeRepo(files) {
  const root = mkdtempSync(join(tmpdir(), 'audit-shard-'))
  for (const [rel, contents] of Object.entries(files)) {
    const full = join(root, rel)
    mkdirSync(join(full, '..'), { recursive: true })
    writeFileSync(full, contents)
  }
  return root
}

/** N synthetic source files under a directory. */
function manyFiles(dir, n) {
  const out = {}
  for (let i = 0; i < n; i++) out[`${dir}/f${String(i).padStart(3, '0')}.js`] = 'export const x = 1\n'
  return out
}

test('single mode when file count fits one shard', () => {
  const root = makeRepo({ 'a.js': 'x', 'b.js': 'y' })
  try {
    const plan = planShards(root, { shardFileCount: 120 })
    assert.equal(plan.mode, 'single')
    assert.equal(plan.shards.length, 1)
    assert.equal(plan.shards[0].name, 'whole-repo')
    assert.equal(plan.totalFiles, 2)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('sharded mode clusters by top-level directory', () => {
  const files = { ...manyFiles('src', 140), ...manyFiles('lib', 140) }
  const root = makeRepo(files)
  try {
    const plan = planShards(root, { shardFileCount: 120, maxShards: 12 })
    assert.equal(plan.mode, 'sharded')
    // Two oversized modules, each subdivided into alphabetical chunks.
    assert.ok(plan.shards.length >= 2)
    // Every original file appears exactly once across all shards.
    const seen = new Set(plan.shards.flatMap(s => s.files))
    assert.equal(seen.size, 280)
    // No shard exceeds the per-shard cap (oversized modules are subdivided).
    for (const shard of plan.shards) assert.ok(shard.fileCount <= 120, `${shard.name} has ${shard.fileCount}`)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('respects maxShards cap by merging', () => {
  // 6 modules of 60 files = 360, cap at 120 file/shard -> 6 shards; cap to 3.
  const files = {}
  for (const dir of ['m1', 'm2', 'm3', 'm4', 'm5', 'm6']) Object.assign(files, manyFiles(dir, 60))
  const root = makeRepo(files)
  try {
    const plan = planShards(root, { shardFileCount: 120, maxShards: 3 })
    assert.equal(plan.mode, 'sharded')
    assert.ok(plan.shards.length <= 3, `got ${plan.shards.length} shards`)
    // Coverage preserved after merging.
    const seen = new Set(plan.shards.flatMap(s => s.files))
    assert.equal(seen.size, 360)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('ignores node_modules, binary assets and gitignored files', () => {
  const files = {
    'src/a.js': 'x',
    'src/logo.png': 'PNGDATA',
    'node_modules/pkg/index.js': 'x',
    '.git/config': 'x',
    // no .gitignore here, so a plain file must show up
    'README2.js': 'x',
  }
  const root = makeRepo(files)
  try {
    const plan = planShards(root, { shardFileCount: 120 })
    const all = plan.shards.flatMap(s => s.files)
    assert.ok(all.includes('src/a.js'))
    assert.ok(all.includes('README2.js'))
    assert.ok(!all.some(f => f.includes('node_modules')))
    assert.ok(!all.some(f => f.endsWith('.png')))
    assert.ok(!all.some(f => f.includes('.git/') || f === '.git/config'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('honours .gitignore rules', () => {
  const files = {
    '.gitignore': 'ignored.js\nbuild/\n',
    'keep.js': 'x',
    'ignored.js': 'x',
    'build/out.js': 'x',
  }
  const root = makeRepo(files)
  try {
    const plan = planShards(root, { shardFileCount: 120 })
    const all = plan.shards.flatMap(s => s.files)
    assert.ok(all.includes('keep.js'))
    assert.ok(!all.includes('ignored.js'))
    assert.ok(!all.some(f => f.startsWith('build/')))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('async walker yields the same plan as the sync walker', async () => {
  const files = { ...manyFiles('src', 200), ...manyFiles('web', 150), 'root.js': 'x' }
  const root = makeRepo(files)
  try {
    const sync = planShards(root, { shardFileCount: 120, maxShards: 12 })
    const async_ = await planShardsAsync(root, { shardFileCount: 120, maxShards: 12 })
    // Same set of files, same shard count, same per-shard membership.
    const norm = plan => plan.shards.map(s => [...s.files].sort()).sort()
    assert.deepEqual(norm(sync), norm(async_))
    assert.equal(sync.mode, async_.mode)
    assert.equal(sync.totalFiles, async_.totalFiles)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('buildShardWorkspaceInfo lists siblings and entry files', () => {
  const plan = {
    mode: 'sharded',
    strategy: 's',
    totalFiles: 4,
    shards: [
      { index: 0, name: 'a', path: 'a', fileCount: 2, files: ['a/index.js', 'a/util.js'] },
      { index: 1, name: 'b', path: 'b', fileCount: 2, files: ['b/server.py', 'b/x.py'] },
    ],
  }
  const info = buildShardWorkspaceInfo(plan, plan.shards[0])
  assert.equal(info.shardCount, 2)
  assert.equal(info.siblingShards.length, 1)
  assert.match(info.siblingShards[0], /^b/)
  assert.ok(info.entryFiles.includes('a/index.js'))
  assert.ok(info.entryFiles.includes('b/server.py'))
})

test('SHARD_STATUS_LABELS covers every stored status', () => {
  for (const key of ['pending', 'running', 'completed', 'failed', 'cancelled']) {
    assert.ok(SHARD_STATUS_LABELS[key], `missing label for ${key}`)
  }
})
