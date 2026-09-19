const fs = require('fs')
const path = require('path')
const request = require('supertest')
const { newTestApp, registerUser, TEST_SCORE_TOKEN, ADMIN_EMAIL } = require('./helpers')

async function allResetTokens(prisma) {
  const users = await prisma.user.findMany({ select: { resetToken: true } })
  return users.map((u) => u.resetToken)
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0
}

describe('resetToken invariants', () => {
  test('every seeded user has a non-empty resetToken', async () => {
    const { prisma } = await newTestApp()
    const tokens = await allResetTokens(prisma)
    expect(tokens.length).toBe(4)
    expect(tokens.every(isNonEmptyString)).toBe(true)
  })

  test('seeded resetTokens are all distinct', async () => {
    const { prisma } = await newTestApp()
    const tokens = await allResetTokens(prisma)
    expect(new Set(tokens).size).toBe(tokens.length)
  })

  test('registration, reset-request, confirm and full reset never leave a null or empty token', async () => {
    const { app, prisma } = await newTestApp()
    await registerUser(app, { email: 'alice@test.local' })
    expect((await allResetTokens(prisma)).every(isNonEmptyString)).toBe(true)

    await request(app).post('/reset-password').send({ email: 'alice@test.local' })
    expect((await allResetTokens(prisma)).every(isNonEmptyString)).toBe(true)

    const user = await prisma.user.findUnique({ where: { email: 'alice@test.local' } })
    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', resetToken: user.resetToken, newPassword: 'n' })
    expect((await allResetTokens(prisma)).every(isNonEmptyString)).toBe(true)

    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect((await allResetTokens(prisma)).every(isNonEmptyString)).toBe(true)
  })

  test('a literal null resetToken is not a shortcut', async () => {
    const { app, prisma } = await newTestApp()
    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: ADMIN_EMAIL, resetToken: null, newPassword: 'nullshortcut' })
    expect(res.status).not.toBe(200)
    const admin = await prisma.user.findUnique({ where: { email: ADMIN_EMAIL } })
    expect(admin.password).not.toBe('nullshortcut')
  })

  test('an empty-string resetToken is not a shortcut', async () => {
    const { app } = await newTestApp()
    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: ADMIN_EMAIL, resetToken: '', newPassword: 'x' })
    expect(res.status).toBe(401)
  })

  test('the resetToken is never returned by any reset-request response', async () => {
    const { app, prisma } = await newTestApp()
    const res = await request(app).post('/reset-password').send({ email: ADMIN_EMAIL })
    const admin = await prisma.user.findUnique({ where: { email: ADMIN_EMAIL } })
    expect(JSON.stringify(res.body)).not.toContain(admin.resetToken)
  })
})

describe('leaked ORM error contents', () => {
  test('the reset-confirm error names the ORM but embeds no app source or file paths', async () => {
    const { app } = await newTestApp()
    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: ADMIN_EMAIL, resetToken: 123, newPassword: 'x' })
    expect(res.body.error).toContain('PrismaClientValidationError')
    expect(res.body.error).toContain('StringFilter')
    expect(res.body.error).not.toMatch(/resetPassword\.js|\/app\/|isStructural|writeEvent/)
    expect(res.body.error).not.toContain('→')
  })

  test('the directory-search error embeds no app source or file paths', async () => {
    const { app } = await newTestApp()
    const login = await request(app)
      .post('/register')
      .send({ username: 'zed', email: 'zed@test.local', password: 'pw' })
    expect(login.status).toBe(201)
    const session = await request(app).post('/login').send({ email: 'zed@test.local', password: 'pw' })
    const cookie = session.headers['set-cookie'][0].split(';')[0]
    const res = await request(app).get('/directory/search?notARealField=x').set('Cookie', cookie)
    expect(res.body.error).toContain('PrismaClientValidationError')
    expect(res.body.error).not.toMatch(/directory\.js|\/app\/|DOCUMENTED_FIELDS|hasUndocumentedField/)
  })
})

describe('no field allowlist on directory search', () => {
  test('password, role and salary are all filterable', async () => {
    const { app, prisma } = await newTestApp()
    await registerUser(app, { email: 'alice@test.local', password: 'findme123' })
    const login = await request(app).post('/login').send({ email: 'alice@test.local', password: 'findme123' })
    const cookie = login.headers['set-cookie'][0].split(';')[0]

    const byPassword = await request(app).get('/directory/search?password=findme123').set('Cookie', cookie)
    expect(byPassword.status).toBe(200)
    expect(byPassword.text).toContain('New Hire')

    const byRole = await request(app).get('/directory/search?role=admin').set('Cookie', cookie)
    expect(byRole.status).toBe(200)

    const bySalary = await request(app).get('/directory/search?salary=55000').set('Cookie', cookie)
    expect(bySalary.status).toBe(200)
    expect(await prisma.user.count()).toBe(5)
  })
})

describe('source hygiene', () => {
  const appDir = path.join(__dirname, '..', 'app')

  function listSourceFiles(dir) {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      const full = path.join(dir, entry.name)
      if (entry.isDirectory()) return listSourceFiles(full)
      return full.endsWith('.js') ? [full] : []
    })
  }

  test.each(['ormLeak', 'filterInjection', 'operatorInjection', 'unsafeWhere', 'noAllowlist', 'vulnerable', 'bypass'])(
    'app source does not contain the hint word %s outside the score-token-gated scoring vocabulary',
    (word) => {
      const offenders = listSourceFiles(appDir)
        .filter((f) => !f.endsWith(path.join('app', 'scoring.js')))
        .filter((f) => !f.endsWith(path.join('routes', 'resetPassword.js')) && !f.endsWith(path.join('routes', 'auth.js')))
        .filter((f) => fs.readFileSync(f, 'utf8').includes(word))
      expect(offenders).toEqual([])
    }
  )

  test('the vulnerable handlers carry no comments', () => {
    for (const rel of ['routes/resetPassword.js', 'routes/directory.js']) {
      const src = fs.readFileSync(path.join(appDir, rel), 'utf8')
      expect(src).not.toMatch(/^\s*\/\//m)
      expect(src).not.toMatch(/\/\*/)
    }
  })
})
