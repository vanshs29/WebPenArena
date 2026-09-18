const fs = require('fs')
const path = require('path')
const { newTestApp, registerAndLogin, getCaseIdForEmail, uploadDocument, listDocuments } = require('./helpers')

describe('document upload', () => {
  test('a filename containing ".." is rejected', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const caseId = getCaseIdForEmail(app, 'alice@test.local')

    const res = await uploadDocument(app, cookie, caseId, '../../etc/passwd')
    expect(res.status).toBe(400)
  })

  test('a filename containing "/" is rejected', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const caseId = getCaseIdForEmail(app, 'alice@test.local')

    const res = await uploadDocument(app, cookie, caseId, 'foo/bar.txt')
    expect(res.status).toBe(400)
  })

  test('a filename beginning with "-" is accepted and appears verbatim on a follow-up list', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const caseId = getCaseIdForEmail(app, 'alice@test.local')

    const upload = await uploadDocument(app, cookie, caseId, '--probe')
    expect(upload.status).toBe(201)

    const list = await listDocuments(app, cookie, caseId)
    expect(list.status).toBe(200)
    expect(list.body.documents).toContain('--probe')
  })

  test('a filename containing spaces and "=" characters is accepted and appears verbatim', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const caseId = getCaseIdForEmail(app, 'alice@test.local')

    const filename = '--checkpoint-action=exec=sh shell.sh'
    const upload = await uploadDocument(app, cookie, caseId, filename)
    expect(upload.status).toBe(201)

    const list = await listDocuments(app, cookie, caseId)
    expect(list.body.documents).toContain(filename)
  })

  test('the underlying file exists on disk with the exact byte-for-byte name', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const caseId = getCaseIdForEmail(app, 'alice@test.local')
    const filename = '--checkpoint-action=exec=sh shell.sh'

    await uploadDocument(app, cookie, caseId, filename, 'payload contents')

    const filePath = path.join(app.locals.uploadsRoot, String(caseId), filename)
    expect(fs.existsSync(filePath)).toBe(true)
    expect(fs.readFileSync(filePath, 'utf8')).toBe('payload contents')
  })

  test('an empty filename is rejected', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const caseId = getCaseIdForEmail(app, 'alice@test.local')

    const res = await uploadDocument(app, cookie, caseId, '')
    expect(res.status).toBe(400)
  })

  test('a filename containing a backslash is rejected', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const caseId = getCaseIdForEmail(app, 'alice@test.local')

    const res = await uploadDocument(app, cookie, caseId, 'foo\\bar.txt')
    expect(res.status).toBe(400)
  })

  test('uploading to a case the caller does not own is rejected', async () => {
    const app = newTestApp()
    const cookieA = await registerAndLogin(app, 'alice@test.local')
    await registerAndLogin(app, 'carol@test.local')
    const carolCaseId = getCaseIdForEmail(app, 'carol@test.local')

    const res = await uploadDocument(app, cookieA, carolCaseId, 'doc.txt')
    expect(res.status).toBe(403)
  })

  test('listing documents requires auth and ownership', async () => {
    const app = newTestApp()
    const cookieA = await registerAndLogin(app, 'alice@test.local')
    await registerAndLogin(app, 'carol@test.local')
    const carolCaseId = getCaseIdForEmail(app, 'carol@test.local')

    const noAuth = await listDocuments(app, '', carolCaseId)
    expect(noAuth.status).toBe(401)

    const wrongOwner = await listDocuments(app, cookieA, carolCaseId)
    expect(wrongOwner.status).toBe(403)
  })
})
