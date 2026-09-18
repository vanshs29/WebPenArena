const request = require('supertest')
const { newTestApp, registerAndLogin } = require('./helpers')

describe('public and page routes', () => {
  test('landing page renders', async () => {
    const app = newTestApp()
    const res = await request(app).get('/')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Portstone')
  })

  test('login and register pages render', async () => {
    const app = newTestApp()
    expect((await request(app).get('/login')).status).toBe(200)
    expect((await request(app).get('/register')).status).toBe(200)
  })

  test('a shipment detail page is reachable by its owner', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const dashboard = await request(app).get('/dashboard').set('Cookie', cookie)
    const match = dashboard.text.match(/\/shipments\/(\d+)/)
    expect(match).not.toBeNull()

    const res = await request(app).get(`/shipments/${match[1]}`).set('Cookie', cookie)
    expect(res.status).toBe(200)
  })

  test('a shipment cannot be viewed by a different user (ownership-scoped)', async () => {
    const app = newTestApp()
    const cookieA = await registerAndLogin(app, 'alice@test.local', 'password123', 'alice')
    const dashboardA = await request(app).get('/dashboard').set('Cookie', cookieA)
    const match = dashboardA.text.match(/\/shipments\/(\d+)/)

    const cookieB = await registerAndLogin(app, 'bob@test.local', 'password123', 'bob')
    const res = await request(app).get(`/shipments/${match[1]}`).set('Cookie', cookieB)
    expect(res.status).toBe(404)
  })

  test('/shipments/:id requires authentication', async () => {
    const app = newTestApp()
    const res = await request(app).get('/shipments/1')
    expect(res.status).toBe(401)
  })
})
