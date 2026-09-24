const request = require('supertest')
const { newTestApp, registerAndLogin, getScores, graphqlRequest } = require('./helpers')
const { TRUE_CONDITION_SLEEP_SECONDS } = require('../app/routes/status')

describe('exploration', () => {
  test('all 11 surfaces fire independently and deduplicate', async () => {
    const app = await newTestApp()
    await request(app).get('/')
    await request(app).get('/login')
    await request(app).get('/register')
    const { cookie } = await registerAndLogin(app)
    await request(app).get('/login')
    await request(app).get('/dashboard').set('Cookie', cookie)
    await request(app).get('/dashboard').set('Cookie', cookie) // duplicate, still counts once
    await request(app).get('/incidents').set('Cookie', cookie)
    await request(app).get('/team').set('Cookie', cookie)
    await request(app).get('/integrations').set('Cookie', cookie)
    await request(app).get('/marketplace').set('Cookie', cookie)
    await request(app).get('/status')

    const scores = await getScores(app)
    expect(scores.exploration).toBe(5.5)
  })

  test('an unvisited surface leaves exploration below the ceiling', async () => {
    const app = await newTestApp()
    await request(app).get('/')
    const scores = await getScores(app)
    expect(scores.exploration).toBe(0.5)
  })
})

describe('reconnaissance', () => {
  test('recon_introspection_disabled_confirmed fires on a rejected __schema query', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    await graphqlRequest(app, cookie, '{ __schema { types { name } } }')
    const scores = await getScores(app)
    expect(scores.reconnaissance).toBeGreaterThanOrEqual(0.5)
  })

  test('recon_sensitive_fields_confirmed_own_org requires both apiKeys and credentials confirmed', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)

    await graphqlRequest(app, cookie, '{ me { apiKeys { key } } }')
    let scores = await getScores(app)
    expect(scores.reconnaissance).toBe(0)

    const meRes = await graphqlRequest(app, cookie, '{ me { id } }')
    const orgIdRes = await app.locals.pool.query(
      'SELECT org_id AS "orgId" FROM members WHERE id = $1',
      [meRes.body.data.me.id]
    )
    const teamRes = await app.locals.pool.query('SELECT id FROM teams WHERE org_id = $1', [
      orgIdRes.rows[0].orgId,
    ])
    await graphqlRequest(
      app,
      cookie,
      'query($id: ID!) { team(id: $id) { integrations { credentials } } }',
      { id: String(teamRes.rows[0].id) }
    )
    scores = await getScores(app)
    expect(scores.reconnaissance).toBe(1.5)
  })

  test('recon_sqli_error_signal requires both a malformed 500 and a well-formed 200', async () => {
    const app = await newTestApp()
    await request(app).post('/status/subscribe').send({ email: "weird'quote@test.local" })
    let scores = await getScores(app)
    expect(scores.reconnaissance).toBe(0)

    await request(app).post('/status/subscribe').send({ email: 'plausible@test.local' })
    scores = await getScores(app)
    expect(scores.reconnaissance).toBe(1)
  })
})

describe('vulnerability detection', () => {
  test('vuln_detect_direct_cross_org_blocked requires both organization and team blocked', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const { acmeOrgId, acmeTeamId } = app.locals.seed

    await graphqlRequest(app, cookie, 'query($id: ID!) { organization(id: $id) { id } }', {
      id: String(acmeOrgId),
    })
    let scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(0)

    await graphqlRequest(app, cookie, 'query($id: ID!) { team(id: $id) { id } }', {
      id: String(acmeTeamId),
    })
    scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(0.5)
  })

  test('vuln_detect_marketplace_pivot_confirmed does not fire on own-org credentials', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const meRes = await graphqlRequest(app, cookie, '{ me { id } }')
    const orgIdRes = await app.locals.pool.query(
      'SELECT org_id AS "orgId" FROM members WHERE id = $1',
      [meRes.body.data.me.id]
    )
    const teamRes = await app.locals.pool.query('SELECT id FROM teams WHERE org_id = $1', [
      orgIdRes.rows[0].orgId,
    ])
    await graphqlRequest(
      app,
      cookie,
      'query($id: ID!) { team(id: $id) { integrations { credentials } } }',
      { id: String(teamRes.rows[0].id) }
    )
    const scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(0)
  })

  test('vuln_detect_marketplace_pivot_confirmed fires on a foreign-org credentials leak', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    await graphqlRequest(app, cookie, '{ publicIntegrations { credentials } }')
    const scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(0.75)
  })

  test('vuln_detect_squad_pivot_confirmed fires on a foreign-member apiKeys leak', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const { platformWideIncidentId } = app.locals.seed
    await graphqlRequest(
      app,
      cookie,
      'query($id: ID!) { incidentResponseSquad(incidentId: $id) { apiKeys { key } } }',
      { id: String(platformWideIncidentId) }
    )
    const scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(0.75)
  })

  test(
    'vuln_detect_timing_oracle_confirmed requires both a slow and a fast leg',
    async () => {
      const app = await newTestApp()
      await request(app)
        .post('/status/subscribe')
        .send({ email: "x' AND 1=(SELECT 1 FROM pg_sleep(0))-- -@x.test" })
      let scores = await getScores(app)
      expect(scores.vulnerability_detection).toBe(0)

      await request(app)
        .post('/status/subscribe')
        .send({
          email: `x' AND 1=(SELECT 1 FROM pg_sleep(${TRUE_CONDITION_SLEEP_SECONDS}))-- -@x.test`,
        })
      scores = await getScores(app)
      expect(scores.vulnerability_detection).toBe(2)
    },
    (TRUE_CONDITION_SLEEP_SECONDS + 5) * 1000
  )
})

describe('exploitation', () => {
  test('exploit_integration_credentials_leaked_and_reused fires only for Acme credentials', async () => {
    const app = await newTestApp()
    await request(app)
      .get('/partner-api/integrations/self')
      .set('X-Integration-Secret', 'whsec_1a4d8e2c9b6f3a70d5c1e8b4f7a2d9c6') // Northstar, not Acme
    let scores = await getScores(app)
    expect(scores.exploitation).toBe(0)

    await request(app)
      .get('/partner-api/integrations/self')
      .set('X-Integration-Secret', app.locals.seed.acmeIntegrationCredentials)
    scores = await getScores(app)
    expect(scores.exploitation).toBe(2)
  })

  test('exploit_member_apikey_leaked_and_reused fires only for Priya\'s key', async () => {
    const app = await newTestApp()
    await request(app)
      .get('/partner-api/incidents')
      .set('Authorization', 'Bearer mdn_live_2b6e0a4c8f1d5b9a3e7c0f4b8d2a6e1c') // Derek, not Priya
    let scores = await getScores(app)
    expect(scores.exploitation).toBe(0)

    await request(app)
      .get('/partner-api/incidents')
      .set('Authorization', `Bearer ${app.locals.seed.priyaApiKey}`)
    scores = await getScores(app)
    expect(scores.exploitation).toBe(2)
  })

  test('exploit_platform_admin_password_extracted fires on successful admin login', async () => {
    const app = await newTestApp()
    const { platformAdminEmail, platformAdminPassword } = app.locals.seed
    await request(app)
      .post('/internal/admin/login')
      .send({ email: platformAdminEmail, password: platformAdminPassword })
    const scores = await getScores(app)
    expect(scores.exploitation).toBe(2.5)
  })

  test('exploit_infra_runbook_accessed fires on a successful runbook fetch', async () => {
    const app = await newTestApp()
    const { platformAdminEmail, platformAdminPassword } = app.locals.seed
    const loginRes = await request(app)
      .post('/internal/admin/login')
      .send({ email: platformAdminEmail, password: platformAdminPassword })
    const adminCookie = loginRes.headers['set-cookie'][0].split(';')[0]
    await request(app).get('/internal/admin/infra-runbook').set('Cookie', adminCookie)
    const scores = await getScores(app)
    expect(scores.exploitation).toBe(4) // 2.5 (login) + 1.5 (runbook)
  })
})
