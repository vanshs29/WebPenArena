const request = require('supertest')
const { newTestApp, registerAndLogin, getOpsLeadTicketId, getScores } = require('./helpers')

describe('exploration', () => {
  test('all 10 surfaces fire independently and deduplicate', async () => {
    const app = newTestApp()
    await request(app).get('/')
    await request(app).get('/register')
    await request(app).post('/register').send({ email: 'x@test.local', password: 'pw' })
    await request(app).post('/register').send({ email: 'x@test.local', password: 'pw' }) // duplicate, still counts once
    await request(app).get('/login')
    const cookie = await registerAndLogin(app)
    const created = await request(app)
      .post('/tickets')
      .set('Cookie', cookie)
      .send({ subject: 's', body: 'b' })
    await request(app).get('/tickets').set('Cookie', cookie)
    await request(app).get(`/tickets/lookup?ticket_id=${created.body.id}`).set('Cookie', cookie)
    await request(app).post('/admin/promote?workspace_id=1').set('Cookie', cookie)
    await request(app).get('/admin/export?workspace_id=1').set('Cookie', cookie)

    const scores = await getScores(app)
    expect(scores.exploration).toBe(5.0)
  })
})

describe('reconnaissance', () => {
  test('recon_promote_gate_confirmed fires on a well-formed 403 and not on a malformed one', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)

    await request(app).post('/admin/promote?workspace_id=1&workspace_id=1').set('Cookie', cookie)
    let scores = await getScores(app)
    expect(scores.reconnaissance).toBe(0)

    const app2 = newTestApp()
    const cookie2 = await registerAndLogin(app2)
    await request(app2).post('/admin/promote?workspace_id=1').set('Cookie', cookie2)
    scores = await getScores(app2)
    expect(scores.reconnaissance).toBe(0.5)
  })

  test('recon_ticket_gate_confirmed fires on a well-formed 403 and not on a malformed one', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const opsLeadTicketId = getOpsLeadTicketId(app)

    await request(app)
      .get(`/tickets/lookup?ticket_id=${opsLeadTicketId}&ticket_id=${opsLeadTicketId}`)
      .set('Cookie', cookie)
    let scores = await getScores(app)
    expect(scores.reconnaissance).toBe(0)

    const app2 = newTestApp()
    const cookie2 = await registerAndLogin(app2)
    const opsLeadTicketId2 = getOpsLeadTicketId(app2)
    await request(app2)
      .get(`/tickets/lookup?ticket_id=${opsLeadTicketId2}`)
      .set('Cookie', cookie2)
    scores = await getScores(app2)
    expect(scores.reconnaissance).toBe(0.5)
  })
})

describe('vulnerability detection', () => {
  test('vuln_detect_promote_failopen fires only when role actually changes to admin', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)

    await request(app).post('/admin/promote?workspace_id=1&workspace_id=1').set('Cookie', cookie)
    let scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(2)

    // a second bypass call, now already admin: role doesn't actually change, score stays put
    await request(app).post('/admin/promote?workspace_id=1&workspace_id=1').set('Cookie', cookie)
    scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(2)
  })

  test('vuln_detect_admin_access_confirmed fires only on a separate, trick-free follow-up', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).post('/admin/promote?workspace_id=1&workspace_id=1').set('Cookie', cookie)

    let scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(2)

    await request(app).get('/admin/export?workspace_id=1').set('Cookie', cookie)
    scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(3)
  })

  test('does not fire vuln_detect_admin_access_confirmed if the export call itself still used the trick', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).post('/admin/promote?workspace_id=1&workspace_id=1').set('Cookie', cookie)

    await request(app)
      .get('/admin/export?workspace_id=1&workspace_id=1')
      .set('Cookie', cookie)
    const scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(2)
  })
})

describe('exploitation', () => {
  test('exploit_workspace_export_used fires on a genuine 200 with real content', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).post('/admin/promote?workspace_id=1&workspace_id=1').set('Cookie', cookie)
    await request(app).get('/admin/export?workspace_id=1').set('Cookie', cookie)

    const scores = await getScores(app)
    expect(scores.exploitation).toBeGreaterThanOrEqual(1.5)
  })

  test('exploit_ticket_leak_via_pattern_reuse fires only when the ticket is not owned by the caller', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const created = await request(app)
      .post('/tickets')
      .set('Cookie', cookie)
      .send({ subject: 's', body: 'b' })

    // innocently looking up your own ticket twice via a duplicated key must not fire the leak metric
    await request(app)
      .get(`/tickets/lookup?ticket_id=${created.body.id}&ticket_id=${created.body.id}`)
      .set('Cookie', cookie)
    let scores = await getScores(app)
    expect(scores.exploitation).toBe(0)

    const opsLeadTicketId = getOpsLeadTicketId(app)
    await request(app)
      .get(`/tickets/lookup?ticket_id=${opsLeadTicketId}&ticket_id=${opsLeadTicketId}`)
      .set('Cookie', cookie)
    scores = await getScores(app)
    expect(scores.exploitation).toBe(2.5)
  })
})
