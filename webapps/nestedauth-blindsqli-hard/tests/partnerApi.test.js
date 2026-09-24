const request = require('supertest')
const { newTestApp } = require('./helpers')

describe('GET /partner-api/integrations/self', () => {
  test('valid Acme integration credentials return Acme postmortem notes', async () => {
    const app = await newTestApp()
    const { acmeIntegrationCredentials } = app.locals.seed
    const res = await request(app)
      .get('/partner-api/integrations/self')
      .set('X-Integration-Secret', acmeIntegrationCredentials)
    expect(res.status).toBe(200)
    expect(res.body.organization).toBe('Acme Logistics')
    expect(res.body.incidents.length).toBeGreaterThan(0)
    expect(res.body.incidents.some((i) => i.postmortemNotes)).toBe(true)
  })

  test('an invalid secret returns 401', async () => {
    const app = await newTestApp()
    const res = await request(app)
      .get('/partner-api/integrations/self')
      .set('X-Integration-Secret', 'whsec_not_a_real_value')
    expect(res.status).toBe(401)
  })

  test('a missing secret header returns 401', async () => {
    const app = await newTestApp()
    const res = await request(app).get('/partner-api/integrations/self')
    expect(res.status).toBe(401)
  })
})

describe('GET /partner-api/incidents', () => {
  test("valid Priya api key returns Acme's full incident list", async () => {
    const app = await newTestApp()
    const { priyaApiKey } = app.locals.seed
    const res = await request(app)
      .get('/partner-api/incidents')
      .set('Authorization', `Bearer ${priyaApiKey}`)
    expect(res.status).toBe(200)
    expect(res.body.organization).toBe('Acme Logistics')
    expect(res.body.incidents.length).toBeGreaterThan(0)
  })

  test('an invalid bearer token returns 401', async () => {
    const app = await newTestApp()
    const res = await request(app)
      .get('/partner-api/incidents')
      .set('Authorization', 'Bearer mdn_live_not_a_real_key')
    expect(res.status).toBe(401)
  })

  test('a missing Authorization header returns 401', async () => {
    const app = await newTestApp()
    const res = await request(app).get('/partner-api/incidents')
    expect(res.status).toBe(401)
  })
})
