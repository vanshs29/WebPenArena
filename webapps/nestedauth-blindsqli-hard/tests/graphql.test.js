const { newTestApp, registerAndLogin, graphqlRequest } = require('./helpers')

describe('GraphQL — introspection', () => {
  test('a __schema query is rejected, not answered', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const res = await graphqlRequest(app, cookie, '{ __schema { types { name } } }')
    expect(res.body.data).toBeFalsy()
    expect(res.body.errors).toBeTruthy()
    expect(res.body.errors[0].message).toMatch(/introspection has been disabled/i)
  })
})

describe('GraphQL — unauthenticated access', () => {
  test('requires a session cookie', async () => {
    const app = await newTestApp()
    const res = await graphqlRequest(app, '', '{ me { id } }')
    expect(res.status).toBe(401)
  })
})

describe('GraphQL — me and correctly-gated own-org queries', () => {
  test('me returns the caller', async () => {
    const app = await newTestApp()
    const { cookie, email } = await registerAndLogin(app, { name: 'Own Caller' })
    const res = await graphqlRequest(app, cookie, '{ me { id name email } }')
    expect(res.body.data.me.name).toBe('Own Caller')
    expect(res.body.data.me.email).toBe(email)
  })

  test('organization(id: ownOrgId) returns real data', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const meRes = await graphqlRequest(app, cookie, '{ me { id } }')
    const orgIdRes = await app.locals.pool.query('SELECT org_id AS "orgId" FROM members WHERE id = $1', [
      meRes.body.data.me.id,
    ])
    const ownOrgId = orgIdRes.rows[0].orgId
    const res = await graphqlRequest(
      app,
      cookie,
      'query($id: ID!) { organization(id: $id) { id name } }',
      { id: String(ownOrgId) }
    )
    expect(res.body.errors).toBeFalsy()
    expect(res.body.data.organization.id).toBe(String(ownOrgId))
  })

  test('team(id: ownTeamId) returns real data', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const meRes = await graphqlRequest(app, cookie, '{ me { id } }')
    const orgIdRes = await app.locals.pool.query('SELECT org_id AS "orgId" FROM members WHERE id = $1', [
      meRes.body.data.me.id,
    ])
    const ownOrgId = orgIdRes.rows[0].orgId
    const teamRes = await app.locals.pool.query('SELECT id FROM teams WHERE org_id = $1', [ownOrgId])
    const ownTeamId = teamRes.rows[0].id

    const res = await graphqlRequest(
      app,
      cookie,
      'query($id: ID!) { team(id: $id) { id name } }',
      { id: String(ownTeamId) }
    )
    expect(res.body.errors).toBeFalsy()
    expect(res.body.data.team.id).toBe(String(ownTeamId))
  })
})

describe('GraphQL — direct cross-org access is correctly blocked', () => {
  test('organization(id: foreignId) returns an error, not data', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const { acmeOrgId } = app.locals.seed

    const res = await graphqlRequest(
      app,
      cookie,
      'query($id: ID!) { organization(id: $id) { id name } }',
      { id: String(acmeOrgId) }
    )
    expect(res.body.data.organization).toBeFalsy()
    expect(res.body.errors).toBeTruthy()
  })

  test('team(id: foreignId) returns an error, not data', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const { acmeTeamId } = app.locals.seed

    const res = await graphqlRequest(
      app,
      cookie,
      'query($id: ID!) { team(id: $id) { id name } }',
      { id: String(acmeTeamId) }
    )
    expect(res.body.data.team).toBeFalsy()
    expect(res.body.errors).toBeTruthy()
  })
})

describe('GraphQL — the vulnerability: field-level resolvers ignore ownership', () => {
  test('own-org apiKeys and credentials are queryable via legitimate paths', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)

    const apiKeysRes = await graphqlRequest(app, cookie, '{ me { apiKeys { id label key } } }')
    expect(apiKeysRes.body.errors).toBeFalsy()
    expect(Array.isArray(apiKeysRes.body.data.me.apiKeys)).toBe(true)

    const meRes = await graphqlRequest(app, cookie, '{ me { id } }')
    const orgIdRes = await app.locals.pool.query(
      'SELECT org_id AS "orgId" FROM members WHERE id = $1',
      [meRes.body.data.me.id]
    )
    const teamRes = await app.locals.pool.query('SELECT id FROM teams WHERE org_id = $1', [
      orgIdRes.rows[0].orgId,
    ])
    const credsRes = await graphqlRequest(
      app,
      cookie,
      'query($id: ID!) { team(id: $id) { integrations { id credentials } } }',
      { id: String(teamRes.rows[0].id) }
    )
    expect(credsRes.body.errors).toBeFalsy()
  })

  test('publicIntegrations { credentials } leaks a foreign org secret', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const { acmeIntegrationCredentials } = app.locals.seed

    const res = await graphqlRequest(
      app,
      cookie,
      '{ publicIntegrations { id name credentials } }'
    )
    expect(res.body.errors).toBeFalsy()
    const leaked = res.body.data.publicIntegrations.find(
      (i) => i.credentials === acmeIntegrationCredentials
    )
    expect(leaked).toBeTruthy()
  })

  test('incidentResponseSquad { apiKeys } leaks a foreign member key', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const { platformWideIncidentId, priyaApiKey } = app.locals.seed

    const res = await graphqlRequest(
      app,
      cookie,
      'query($id: ID!) { incidentResponseSquad(incidentId: $id) { id name apiKeys { id label key } } }',
      { id: String(platformWideIncidentId) }
    )
    expect(res.body.errors).toBeFalsy()
    const allKeys = res.body.data.incidentResponseSquad.flatMap((m) => m.apiKeys.map((k) => k.key))
    expect(allKeys).toContain(priyaApiKey)
  })

  test('incidentResponseSquad returns members from multiple organizations', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const { platformWideIncidentId } = app.locals.seed

    const res = await graphqlRequest(
      app,
      cookie,
      'query($id: ID!) { incidentResponseSquad(incidentId: $id) { id name } }',
      { id: String(platformWideIncidentId) }
    )
    expect(res.body.data.incidentResponseSquad.length).toBeGreaterThanOrEqual(3)
  })
})
