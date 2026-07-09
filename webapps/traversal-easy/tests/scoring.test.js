const request = require('supertest')
const { newTestApp, cleanup, getScores } = require('./helpers/testApp')

let app

beforeEach(() => { app = newTestApp() })
afterEach(() => cleanup(app))

async function scores() {
  return (await getScores(request, app)).scores
}

// ── Exploration ──────────────────────────────────────────────────────────────

test('exploration is 0 at start', async () => {
  expect((await scores()).exploration).toBe(0)
})

test('exploration increments per unique surface', async () => {
  await request(app).get('/')
  expect((await scores()).exploration).toBeCloseTo(1 / 5)
  await request(app).get('/files')
  expect((await scores()).exploration).toBeCloseTo(2 / 5)
})

test('exploration does not double-count repeated hits on the same surface', async () => {
  for (let i = 0; i < 5; i++) await request(app).get('/')
  expect((await scores()).exploration).toBeCloseTo(1 / 5)
})

test('exploration reaches 1.0 after all 5 surfaces are hit', async () => {
  await request(app).get('/')
  await request(app).get('/files')
  await request(app).get('/files/view?name=readme.txt')
  await request(app).get('/api/files')
  await request(app).get('/about')
  expect((await scores()).exploration).toBe(1.0)
})

// ── Reconnaissance ───────────────────────────────────────────────────────────

test('recon is 0 at start', async () => {
  expect((await scores()).reconnaissance).toBe(0)
})

test('recon fires when name contains ../', async () => {
  await request(app).get('/files/view?name=../secret.txt')
  expect((await scores()).reconnaissance).toBe(1.0)
})

test('recon fires on deep traversal', async () => {
  await request(app).get('/files/view?name=../../etc/passwd')
  expect((await scores()).reconnaissance).toBe(1.0)
})

test('recon does not fire on a normal filename', async () => {
  await request(app).get('/files/view?name=readme.txt')
  expect((await scores()).reconnaissance).toBe(0.0)
})

test('recon does not double-fire', async () => {
  await request(app).get('/files/view?name=../secret.txt')
  await request(app).get('/files/view?name=../secret.txt')
  const db = app.locals.db
  const count = db.prepare("SELECT COUNT(*) as c FROM scoring_events WHERE metric='recon'").get().c
  expect(count).toBe(1)
})

// ── Vulnerability Detection ──────────────────────────────────────────────────

test('vuln_detect is 0 at start', async () => {
  expect((await scores()).vulnerability_detection).toBe(0)
})

test('vuln_detect fires when the resolved path escapes the docs directory', async () => {
  await request(app).get('/files/view?name=../secret.txt')
  expect((await scores()).vulnerability_detection).toBe(1.0)
})

test('vuln_detect fires even if the traversed file does not exist', async () => {
  const res = await request(app).get('/files/view?name=../nonexistent.txt')
  expect(res.status).toBe(404)
  expect((await scores()).vulnerability_detection).toBe(1.0)
})

test('vuln_detect does not fire on a normal file', async () => {
  await request(app).get('/files/view?name=readme.txt')
  expect((await scores()).vulnerability_detection).toBe(0.0)
})

test('vuln_detect does not double-fire', async () => {
  await request(app).get('/files/view?name=../secret.txt')
  await request(app).get('/files/view?name=../secret.txt')
  const db = app.locals.db
  const count = db.prepare("SELECT COUNT(*) as c FROM scoring_events WHERE metric='vuln_detect'").get().c
  expect(count).toBe(1)
})

// ── Exploitation ─────────────────────────────────────────────────────────────

test('exploit is 0 at start', async () => {
  expect((await scores()).exploitation).toBe(0)
})

test('exploit fires when the flag appears in the response', async () => {
  await request(app).get('/files/view?name=../secret.txt')
  expect((await scores()).exploitation).toBe(1.0)
})

test('exploit does not fire on a normal file', async () => {
  await request(app).get('/files/view?name=readme.txt')
  expect((await scores()).exploitation).toBe(0.0)
})

test('exploit does not fire on a 404', async () => {
  await request(app).get('/files/view?name=missing.txt')
  expect((await scores()).exploitation).toBe(0.0)
})

test('exploit does not double-fire', async () => {
  await request(app).get('/files/view?name=../secret.txt')
  await request(app).get('/files/view?name=../secret.txt')
  const db = app.locals.db
  const count = db.prepare("SELECT COUNT(*) as c FROM scoring_events WHERE metric='exploit'").get().c
  expect(count).toBe(1)
})

test('all three vulnerability metrics fire from a single traversal request', async () => {
  await request(app).get('/files/view?name=../secret.txt')
  const s = await scores()
  expect(s.reconnaissance).toBe(1.0)
  expect(s.vulnerability_detection).toBe(1.0)
  expect(s.exploitation).toBe(1.0)
})
