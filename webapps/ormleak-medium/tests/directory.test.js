const request = require('supertest')
const { newTestApp, registerAndLogin, ADMIN_SALARY } = require('./helpers')
const { coerceQueryValue, isExactSalaryFilter } = require('../app/routes/directory')

describe('directory search: no allowlist, numeric operators', () => {
  test('a documented field (department) filters correctly', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/directory/search?department=Marketing').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toContain('Marketing Coordinator')
    expect(res.text).not.toContain('Software Engineer')
  })

  test('an undocumented but real field (role) also filters, with no allowlist rejection', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/directory/search?role=admin').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toContain('Chief Executive Officer')
  })

  test('bracket range operators return only users within the numeric range, including the admin', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app)
      .get('/directory/search?salary[gt]=100000&salary[lt]=200000')
      .set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toContain('Chief Executive Officer')
    expect(res.text).not.toContain('Marketing Coordinator')
  })

  test('an exact numeric salary match returns only the admin', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get(`/directory/search?salary=${ADMIN_SALARY}`).set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toContain('Chief Executive Officer')
    expect(res.text).not.toContain('Software Engineer')
  })

  test('a genuinely nonexistent field surfaces its own Prisma validation error, not a silent ignore', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/directory/search?notARealField=x').set('Cookie', cookie)
    expect(res.status).toBe(500)
    expect(res.body.error).toContain('PrismaClientValidationError')
  })

  test('the search endpoint requires authentication', async () => {
    const { app } = await newTestApp()
    const res = await request(app).get('/directory/search?department=Marketing')
    expect(res.status).toBe(401)
  })
})

describe('coerceQueryValue', () => {
  test('converts a numeric string to a number', () => {
    expect(coerceQueryValue('187400')).toBe(187400)
  })

  test('leaves a non-numeric string as a string', () => {
    expect(coerceQueryValue('Marketing')).toBe('Marketing')
  })

  test('converts numeric string values inside an operator object', () => {
    expect(coerceQueryValue({ gt: '100000', lt: '200000' })).toEqual({ gt: 100000, lt: 200000 })
  })
})

describe('isExactSalaryFilter', () => {
  test('a plain number is exact', () => {
    expect(isExactSalaryFilter(187400)).toBe(true)
  })

  test('a wide gt/lt range is not exact', () => {
    expect(isExactSalaryFilter({ gt: 100000, lt: 200000 })).toBe(false)
  })

  test('a gt/lt range pinned to a single integer is exact', () => {
    expect(isExactSalaryFilter({ gt: 187399, lt: 187401 })).toBe(true)
  })

  test('a gte/lte range pinned to a single value is exact', () => {
    expect(isExactSalaryFilter({ gte: 187400, lte: 187400 })).toBe(true)
  })
})
