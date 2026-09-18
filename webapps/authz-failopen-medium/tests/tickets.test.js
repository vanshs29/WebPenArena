const request = require('supertest')
const { newTestApp, registerAndLogin, getOpsLeadTicketId } = require('./helpers')

describe('creating and listing tickets', () => {
  test('POST /tickets stores the ticket with the caller as owner', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app)
      .post('/tickets')
      .set('Cookie', cookie)
      .send({ subject: 'Printer broken', body: 'Help please' })
    expect(res.status).toBe(201)

    const db = app.locals.db
    const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(res.body.id)
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get('alice@test.local')
    expect(ticket.owner_id).toBe(user.id)
  })

  test('GET /tickets lists only the caller\'s own tickets', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app)
      .post('/tickets')
      .set('Cookie', cookie)
      .send({ subject: 'My ticket', body: 'body text' })

    const res = await request(app).get('/tickets').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toContain('My ticket')
    expect(res.text).not.toContain('Rotating the shipping-carrier API key')
  })

  test('POST /tickets rejects a missing body with 400', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).post('/tickets').set('Cookie', cookie).send({ subject: 'x' })
    expect(res.status).toBe(400)
  })
})

describe('GET /tickets/lookup under normal input', () => {
  test('returns the caller\'s own ticket', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const created = await request(app)
      .post('/tickets')
      .set('Cookie', cookie)
      .send({ subject: 'My ticket', body: 'body text' })

    const res = await request(app)
      .get(`/tickets/lookup?ticket_id=${created.body.id}`)
      .set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.body.subject).toBe('My ticket')
  })

  test('returns 403 for a real, non-owned ticket id', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const opsLeadTicketId = getOpsLeadTicketId(app)

    const res = await request(app)
      .get(`/tickets/lookup?ticket_id=${opsLeadTicketId}`)
      .set('Cookie', cookie)
    expect(res.status).toBe(403)
  })

  test('returns 404 for a nonexistent ticket id', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/tickets/lookup?ticket_id=999999').set('Cookie', cookie)
    expect(res.status).toBe(404)
  })

  test('returns 400 when ticket_id is omitted', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/tickets/lookup').set('Cookie', cookie)
    expect(res.status).toBe(400)
  })

  test('requires auth', async () => {
    const app = newTestApp()
    const res = await request(app).get('/tickets/lookup?ticket_id=1')
    expect(res.status).toBe(401)
  })
})

describe('multiple tickets', () => {
  test('a second member only ever sees their own tickets, never another member\'s', async () => {
    const app = newTestApp()
    const cookieA = await registerAndLogin(app, 'alice@test.local', 'password123')
    const createdA = await request(app)
      .post('/tickets')
      .set('Cookie', cookieA)
      .send({ subject: 'Alice ticket', body: 'body' })

    const cookieB = await registerAndLogin(app, 'bob@test.local', 'password123')
    const res = await request(app).get('/tickets').set('Cookie', cookieB)
    expect(res.text).not.toContain('Alice ticket')

    const lookup = await request(app)
      .get(`/tickets/lookup?ticket_id=${createdA.body.id}`)
      .set('Cookie', cookieB)
    expect(lookup.status).toBe(403)
  })
})
