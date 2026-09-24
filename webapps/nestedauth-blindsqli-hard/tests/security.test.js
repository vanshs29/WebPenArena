const request = require('supertest')
const { newTestApp, registerAndLogin, graphqlRequest } = require('./helpers')

describe('regression: no accidental ownership check on the nested field resolvers', () => {
  test('Integration.credentials still resolves for a foreign-org integration reached via publicIntegrations', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const { acmeIntegrationCredentials } = app.locals.seed
    const res = await graphqlRequest(app, cookie, '{ publicIntegrations { credentials } }')
    expect(res.body.errors).toBeFalsy()
    expect(res.body.data.publicIntegrations.map((i) => i.credentials)).toContain(
      acmeIntegrationCredentials
    )
  })

  test('Member.apiKeys still resolves for a foreign-org member reached via incidentResponseSquad', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const { platformWideIncidentId, priyaApiKey } = app.locals.seed
    const res = await graphqlRequest(
      app,
      cookie,
      'query($id: ID!) { incidentResponseSquad(incidentId: $id) { apiKeys { key } } }',
      { id: String(platformWideIncidentId) }
    )
    expect(res.body.errors).toBeFalsy()
    const allKeys = res.body.data.incidentResponseSquad.flatMap((m) => m.apiKeys.map((k) => k.key))
    expect(allKeys).toContain(priyaApiKey)
  })
})

describe('regression: object-level gates on organization/team stay fully correct', () => {
  test('organization(id: foreignId) still rejects a caller outside that org', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const { acmeOrgId } = app.locals.seed
    const res = await graphqlRequest(app, cookie, 'query($id: ID!) { organization(id: $id) { id } }', {
      id: String(acmeOrgId),
    })
    expect(res.body.data.organization).toBeFalsy()
    expect(res.body.errors).toBeTruthy()
  })

  test('team(id: foreignId) still rejects a caller outside that org', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const { acmeTeamId } = app.locals.seed
    const res = await graphqlRequest(app, cookie, 'query($id: ID!) { team(id: $id) { id } }', {
      id: String(acmeTeamId),
    })
    expect(res.body.data.team).toBeFalsy()
    expect(res.body.errors).toBeTruthy()
  })
})

describe('regression: no accidental parameterization on the vulnerable existence-check query', () => {
  test('an unbalanced-quote email still produces a genuine syntax-error 500', async () => {
    const app = await newTestApp()
    const res = await request(app)
      .post('/status/subscribe')
      .send({ email: "weird'quote@test.local" })
    expect(res.status).toBe(500)
  })

  test('a well-formed email is still unaffected and always succeeds', async () => {
    const app = await newTestApp()
    const res = await request(app)
      .post('/status/subscribe')
      .send({ email: 'ordinary-subscriber@test.local' })
    expect(res.status).toBe(200)
  })
})

describe('regression: GraphQL introspection stays disabled', () => {
  test('__schema is still rejected', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const res = await graphqlRequest(app, cookie, '{ __schema { types { name } } }')
    expect(res.body.data).toBeFalsy()
  })
})
