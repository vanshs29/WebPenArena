const request = require('supertest')
const { newTestApp, registerAndLogin } = require('./helpers')

const AUTHENTICATED_PAGES = [
  '/dashboard',
  '/incidents',
  '/team',
  '/integrations',
  '/marketplace',
  '/partners',
  '/developers',
]

describe('ordinary authenticated pages', () => {
  test.each(AUTHENTICATED_PAGES)('%s requires authentication', async (pagePath) => {
    const app = await newTestApp()
    const res = await request(app).get(pagePath)
    expect(res.status).toBe(401)
  })

  test.each(AUTHENTICATED_PAGES)('%s renders for an authenticated member', async (pagePath) => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const res = await request(app).get(pagePath).set('Cookie', cookie)
    expect(res.status).toBe(200)
  })

  test('/integrations embeds a GraphQL query requesting credentials on the caller\'s own team', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const res = await request(app).get('/integrations').set('Cookie', cookie)
    expect(res.text).toContain('credentials')
    expect(res.text).toContain('/graphql')
  })

  test('/team embeds a GraphQL query requesting the caller\'s own apiKeys', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const res = await request(app).get('/team').set('Cookie', cookie)
    expect(res.text).toContain('apiKeys')
    expect(res.text).toContain('/graphql')
  })

  test('/developers does not name apiKeys/credentials as sensitive', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const res = await request(app).get('/developers').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text.toLowerCase()).not.toMatch(/sensitive|secret field|do not query|should not/)
  })
})

describe('public status page', () => {
  test('renders without authentication', async () => {
    const app = await newTestApp()
    const res = await request(app).get('/status')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Meridian Core API Elevated Latency')
  })
})
