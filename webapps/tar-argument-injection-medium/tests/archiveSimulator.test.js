const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')
const Database = require('better-sqlite3')
const { initDb } = require('../app/db')
const { compileCase, runArchiveCycle } = require('../app/archiveSimulator')

function newScratchDirs() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `ashwell-sim-test-${crypto.randomUUID()}-`))
  const uploadsRoot = path.join(root, 'uploads')
  const archiveRoot = path.join(root, 'archives')
  fs.mkdirSync(uploadsRoot, { recursive: true })
  fs.mkdirSync(archiveRoot, { recursive: true })
  return { uploadsRoot, archiveRoot }
}

describe('archive simulator', () => {
  let db

  beforeEach(() => {
    db = initDb(':memory:')
  })

  test('compileCase updates last_compiled_at before invoking tar, even if tar never resolves', () => {
    const { uploadsRoot, archiveRoot } = newScratchDirs()
    const { lastInsertRowid: userId } = db
      .prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)')
      .run('alice', 'alice@test.local', 'pw')
    const { lastInsertRowid: caseId } = db
      .prepare('INSERT INTO cases (user_id, case_number, last_compiled_at) VALUES (?, ?, NULL)')
      .run(userId, 'ASH-000001')

    const caseDir = path.join(uploadsRoot, String(caseId))
    fs.mkdirSync(caseDir, { recursive: true })
    fs.writeFileSync(path.join(caseDir, 'note.txt'), 'hello')

    jest.spyOn(require('child_process'), 'execFile').mockImplementation(() => {})

    compileCase(db, caseId, { uploadsRoot, archiveRoot })

    const row = db.prepare('SELECT last_compiled_at FROM cases WHERE id = ?').get(caseId)
    expect(row.last_compiled_at).not.toBeNull()

    require('child_process').execFile.mockRestore()
  })

  test('a case with an empty directory is skipped without error', () => {
    const { uploadsRoot, archiveRoot } = newScratchDirs()
    const { lastInsertRowid: userId } = db
      .prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)')
      .run('alice', 'alice@test.local', 'pw')
    const { lastInsertRowid: caseId } = db
      .prepare('INSERT INTO cases (user_id, case_number, last_compiled_at) VALUES (?, ?, NULL)')
      .run(userId, 'ASH-000001')

    const caseDir = path.join(uploadsRoot, String(caseId))
    fs.mkdirSync(caseDir, { recursive: true })

    expect(() => compileCase(db, caseId, { uploadsRoot, archiveRoot })).not.toThrow()
    const row = db.prepare('SELECT last_compiled_at FROM cases WHERE id = ?').get(caseId)
    expect(row.last_compiled_at).toBeNull()
  })

  test('a case with no uploads directory at all is skipped without error', () => {
    const { uploadsRoot, archiveRoot } = newScratchDirs()
    const { lastInsertRowid: userId } = db
      .prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)')
      .run('alice', 'alice@test.local', 'pw')
    const { lastInsertRowid: caseId } = db
      .prepare('INSERT INTO cases (user_id, case_number, last_compiled_at) VALUES (?, ?, NULL)')
      .run(userId, 'ASH-000001')

    expect(() => compileCase(db, caseId, { uploadsRoot, archiveRoot })).not.toThrow()
  })

  test('a tar invocation that exits non-zero does not crash the process', () => {
    const { uploadsRoot, archiveRoot } = newScratchDirs()
    const { lastInsertRowid: userId } = db
      .prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)')
      .run('alice', 'alice@test.local', 'pw')
    const { lastInsertRowid: caseId } = db
      .prepare('INSERT INTO cases (user_id, case_number, last_compiled_at) VALUES (?, ?, NULL)')
      .run(userId, 'ASH-000001')

    const caseDir = path.join(uploadsRoot, String(caseId))
    fs.mkdirSync(caseDir, { recursive: true })
    fs.writeFileSync(path.join(caseDir, 'note.txt'), 'hello')

    const realExecFile = require('child_process').execFile
    jest.spyOn(require('child_process'), 'execFile').mockImplementation((cmd, args, opts, cb) => {
      cb(new Error('tar failed'), '', 'boom')
    })

    expect(() => compileCase(db, caseId, { uploadsRoot, archiveRoot })).not.toThrow()

    require('child_process').execFile.mockRestore()
  })

  test('runArchiveCycle processes every case in the DB, not just one', () => {
    const { uploadsRoot, archiveRoot } = newScratchDirs()
    const caseIds = []
    for (const email of ['alice@test.local', 'bob@test.local']) {
      const { lastInsertRowid: userId } = db
        .prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)')
        .run(email.split('@')[0], email, 'pw')
      const { lastInsertRowid: caseId } = db
        .prepare('INSERT INTO cases (user_id, case_number, last_compiled_at) VALUES (?, ?, NULL)')
        .run(userId, `ASH-${String(userId).padStart(6, '0')}`)
      caseIds.push(caseId)
      const caseDir = path.join(uploadsRoot, String(caseId))
      fs.mkdirSync(caseDir, { recursive: true })
      fs.writeFileSync(path.join(caseDir, 'note.txt'), 'hello')
    }

    runArchiveCycle(db, { uploadsRoot, archiveRoot })

    for (const caseId of caseIds) {
      const row = db.prepare('SELECT last_compiled_at FROM cases WHERE id = ?').get(caseId)
      expect(row.last_compiled_at).not.toBeNull()
    }
  })
})
