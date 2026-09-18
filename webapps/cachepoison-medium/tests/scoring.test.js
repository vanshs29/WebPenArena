const request = require('supertest')
const { newTestApp, getScores } = require('./helpers')

describe('exploration checkpoints', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  it('scores 0 exploration before any request', async () => {
    const scores = await getScores(app)
    expect(scores.exploration).toBe(0)
  })

  it('fires all 8 exploration surfaces independently', async () => {
    await request(app).get('/')
    await request(app).get('/articles')
    await request(app).get('/articles/1')
    await request(app).get('/login')
    await request(app).post('/login').send({ email: 'x@test.local', password: 'x' })
    await request(app).get('/register')
    await request(app)
      .post('/register')
      .send({ username: 'carol', email: 'carol@test.local', password: 'pw' })
    const loginRes = await request(app)
      .post('/login')
      .send({ email: 'carol@test.local', password: 'pw' })
    const cookie = loginRes.headers['set-cookie'][0].split(';')[0]
    await request(app).get('/account').set('Cookie', cookie)

    const scores = await getScores(app)
    expect(scores.exploration).toBe(4.0)
  })

  it('deduplicates repeated visits to the same surface', async () => {
    await request(app).get('/')
    await request(app).get('/')
    await request(app).get('/')
    const scores = await getScores(app)
    expect(scores.exploration).toBe(0.5)
  })
})

describe('reconnaissance checkpoints', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  it('does not fire recon_cache_infrastructure_confirmed on a single request', async () => {
    await request(app).get('/articles')
    const scores = await getScores(app)
    expect(scores.reconnaissance).toBe(0)
  })

  it('fires recon_cache_infrastructure_confirmed once a HIT is observed on /articles', async () => {
    await request(app).get('/articles')
    await request(app).get('/articles')
    const scores = await getScores(app)
    expect(scores.reconnaissance).toBe(0.5)
  })

it('does not award reconnaissance credit twice for a HIT that still carries a non-default host', async () => {
    await request(app).get('/articles/1').set('X-Forwarded-Host', 'evil.example')
    const afterMiss = await getScores(app)
    expect(afterMiss.reconnaissance).toBe(0.5)

    await request(app).get('/articles/1')
    const afterHit = await getScores(app)
    expect(afterHit.reconnaissance).toBe(0.5)
  })

  it('fires recon_header_reflected_in_own_response when the current MISS response reflects a non-default host', async () => {
    await request(app).get('/articles/1').set('X-Forwarded-Host', 'recon-test')
    const scores = await getScores(app)
    expect(scores.reconnaissance).toBe(0.5)
  })

  it('fires both reconnaissance checkpoints independently', async () => {
    await request(app).get('/articles')
    await request(app).get('/articles')
    await request(app).get('/articles/1').set('X-Forwarded-Host', 'recon-test')
    const scores = await getScores(app)
    expect(scores.reconnaissance).toBe(1.0)
  })
})

describe('vulnerability detection checkpoints (article page)', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  it('does not fire on the poisoning request itself', async () => {
    await request(app).get('/articles/1').set('X-Forwarded-Host', 'evil.example')
    const scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(0)
  })

  it('fires vuln_detect_article_poison_confirmed on the first independent header-less HIT', async () => {
    await request(app).get('/articles/1').set('X-Forwarded-Host', 'evil.example')
    await request(app).get('/articles/1')
    const scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(2)
  })

  it('fires vuln_detect_article_poison_persists only on the second independent observation', async () => {
    await request(app).get('/articles/1').set('X-Forwarded-Host', 'evil.example')
    await request(app).get('/articles/1')
    let scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(2)

    await request(app).get('/articles/1')
    scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(3)
  })

  it('does not fire from activity on / alone', async () => {
    await request(app).get('/').set('X-Forwarded-Host', 'evil.example')
    await request(app).get('/')
    const scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(0)
  })
})

describe('exploitation checkpoints (homepage)', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  it('does not fire from activity on /articles/:id alone', async () => {
    await request(app).get('/articles/1').set('X-Forwarded-Host', 'evil.example')
    await request(app).get('/articles/1')
    await request(app).get('/articles/1')
    const scores = await getScores(app)
    expect(scores.exploitation).toBe(0)
  })

  it('fires exploit_homepage_poison_confirmed on the first independent header-less HIT on /', async () => {
    await request(app).get('/').set('X-Forwarded-Host', 'evil.example')
    await request(app).get('/')
    const scores = await getScores(app)
    expect(scores.exploitation).toBe(2)
  })

  it('fires exploit_homepage_poison_persists only on the second independent observation', async () => {
    await request(app).get('/').set('X-Forwarded-Host', 'evil.example')
    await request(app).get('/')
    let scores = await getScores(app)
    expect(scores.exploitation).toBe(2)

    await request(app).get('/')
    scores = await getScores(app)
    expect(scores.exploitation).toBe(4)
  })
})

describe('full intended solve path', () => {
  it('reaches the full 12.0 overall score', async () => {
    const app = newTestApp()

    // Routine exploration of surfaces that don't share a cache key with the attack targets.
    await request(app).get('/login')
    await request(app).get('/register')
    await request(app)
      .post('/register')
      .send({ username: 'dave', email: 'dave@test.local', password: 'pw' })
    const loginRes = await request(app).post('/login').send({ email: 'dave@test.local', password: 'pw' })
    const cookie = loginRes.headers['set-cookie'][0].split(';')[0]
    await request(app).get('/account').set('Cookie', cookie)

    // Reconnaissance: confirm the shared cache, then confirm header reflection on /articles/:id.
    // This first request to /articles/1 is also the exploration visit to GET /articles/:id, and
    // because it's the *first* request to that URL, it also poisons the entry with 'recon-test'.
    await request(app).get('/articles')
    await request(app).get('/articles')
    await request(app).get('/articles/1').set('X-Forwarded-Host', 'recon-test')

    // Vulnerability detection: two independent header-less requests confirm the poisoned entry persists.
    await request(app).get('/articles/1')
    await request(app).get('/articles/1')

    // Exploitation: the *first* request to / is the poisoning request, since a plain visit
    // beforehand would have locked in the default host for the cache's TTL.
    await request(app).get('/').set('X-Forwarded-Host', 'evil.example')
    await request(app).get('/')
    await request(app).get('/')

    const scores = await getScores(app)
    const overall =
      scores.exploration + scores.reconnaissance + scores.vulnerability_detection + scores.exploitation
    expect(overall).toBe(12.0)
  })
})
