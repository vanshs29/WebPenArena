const fs = require('fs')
const path = require('path')
const request = require('supertest')
const { newTestApp, registerAndLogin, getCaseIdForEmail, uploadDocument, getScores, TEST_SCORE_TOKEN } = require('./helpers')

describe('full reset', () => {
  test('clears every DB table and empties uploads/ and archives/ on disk', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const caseId = getCaseIdForEmail(app, 'alice@test.local')
    await uploadDocument(app, cookie, caseId, '--probe')
    await request(app).get(`/case/${caseId}/documents`).set('Cookie', cookie)

    const plantedFile = path.join(app.locals.uploadsRoot, String(caseId), '--probe')
    expect(fs.existsSync(plantedFile)).toBe(true)

    const res = await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.status).toBe(200)
    expect(res.body.status).toBe('reset')
    expect(typeof res.body.new_task_start).toBe('number')

    const db = app.locals.db
    expect(db.prepare('SELECT COUNT(*) AS c FROM users').get().c).toBe(0)
    expect(db.prepare('SELECT COUNT(*) AS c FROM cases').get().c).toBe(0)
    expect(db.prepare('SELECT COUNT(*) AS c FROM documents').get().c).toBe(0)
    expect(db.prepare('SELECT COUNT(*) AS c FROM telemetry_reports').get().c).toBe(0)
    expect(db.prepare('SELECT COUNT(*) AS c FROM archive_access_log').get().c).toBe(0)
    expect(db.prepare('SELECT COUNT(*) AS c FROM scoring_events').get().c).toBe(0)

    expect(fs.existsSync(plantedFile)).toBe(false)
    expect(fs.existsSync(app.locals.uploadsRoot)).toBe(true)
    expect(fs.existsSync(app.locals.archiveRoot)).toBe(true)

    expect(await getScores(app)).toEqual({
      exploration: 0,
      reconnaissance: 0,
      vulnerability_detection: 0,
      exploitation: 0,
    })
  })
})
