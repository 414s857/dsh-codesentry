import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { AuditStore } from '../src/store.js'

/** Fresh store in a temp dir; caller must call cleanup(). */
function freshStore() {
  const dir = mkdtempSync(join(tmpdir(), 'audit-store-'))
  const store = new AuditStore(dir)
  return { store, cleanup: () => { store.db.close(); rmSync(dir, { recursive: true, force: true }) } }
}

/** Create a task + run + one finding, returning the finding id. */
function seedFinding(store) {
  const task = store.createTask({ name: 't', repo_path: process.cwd(), prompt_ids: [] })
  const run = store.createRun(task.id, 'manual')
  const { finding } = store.addFinding(task.id, {
    title: 'SQLi',
    severity: 'high',
    run_id: run.id,
    fingerprint: 'fp-1',
    status_note: 'initial note',
  })
  // addFinding does not persist a status_note at creation (status starts 'open'
  // with an empty note); set it explicitly before testing the keep/clear logic.
  store.updateFinding(finding.id, { status_note: 'initial note' })
  return finding.id
}

test('updateFinding keeps fields that are omitted from the patch', () => {
  const { store, cleanup } = freshStore()
  try {
    const id = seedFinding(store)
    store.updateFinding(id, { status: 'verified' })
    const f = store.getFinding(id)
    assert.equal(f.status, 'verified')
    assert.equal(f.status_note, 'initial note') // untouched
  } finally {
    cleanup()
  }
})

test('updateFinding can clear status_note with an explicit empty string', () => {
  const { store, cleanup } = freshStore()
  try {
    const id = seedFinding(store)
    store.updateFinding(id, { status_note: '' })
    assert.equal(store.getFinding(id).status_note, '')
  } finally {
    cleanup()
  }
})

test('updateFinding can clear review fields with explicit null', () => {
  const { store, cleanup } = freshStore()
  try {
    const id = seedFinding(store)
    // Set a review verdict first.
    store.updateFinding(id, { review_status: 'confirmed', review_note: 'ok', reviewed_at: '2026-01-01T00:00:00Z' })
    let f = store.getFinding(id)
    assert.equal(f.review_status, 'confirmed')

    // Reset to pending and explicitly null the timestamp / note.
    store.updateFinding(id, { review_status: 'pending', reviewed_at: null, review_note: '' })
    f = store.getFinding(id)
    assert.equal(f.review_status, 'pending')
    assert.equal(f.reviewed_at, null)
    assert.equal(f.review_note, '')
  } finally {
    cleanup()
  }
})

test('updateFinding with an empty patch changes nothing but updated_at', () => {
  const { store, cleanup } = freshStore()
  try {
    const id = seedFinding(store)
    const before = store.getFinding(id)
    store.updateFinding(id, {})
    const after = store.getFinding(id)
    assert.equal(after.status, before.status)
    assert.equal(after.status_note, before.status_note)
    assert.equal(after.review_status, before.review_status)
  } finally {
    cleanup()
  }
})

test('updateFinding returns undefined for an unknown id', () => {
  const { store, cleanup } = freshStore()
  try {
    assert.equal(store.updateFinding('nope', { status: 'verified' }), undefined)
  } finally {
    cleanup()
  }
})
