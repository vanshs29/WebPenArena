const request = require('supertest')
const { newTestApp, SEED_PACKAGE_NAME } = require('./helpers')

describe('status and telemetry surfaces', () => {
  test('build-info discloses the internal package name, version, and registry URL', async () => {
    const app = newTestApp()
    const res = await request(app).get('/status/build-info')

    expect(res.status).toBe(200)
    const dep = res.body.dependencies.find((d) => d.name === SEED_PACKAGE_NAME)
    expect(dep).toBeDefined()
    expect(dep.version).toBe('1.0.2')
    expect(dep.registry).toContain('/registry')
  })

  test('telemetry accepts and stores an arbitrary reported payload', async () => {
    const app = newTestApp()
    const post = await request(app).post('/status/telemetry').send({ service: 'ci', value: 'hello' })
    expect(post.status).toBe(201)

    const get = await request(app).get('/status/telemetry')
    expect(get.status).toBe(200)
    expect(get.body.reports.some((r) => r.payload.value === 'hello')).toBe(true)
  })

  test('status page renders', async () => {
    const app = newTestApp()
    const res = await request(app).get('/status')
    expect(res.status).toBe(200)
  })

  test('build-info never discloses the billing API key', async () => {
    const app = newTestApp()
    const res = await request(app).get('/status/build-info')
    expect(JSON.stringify(res.body)).not.toContain('billing')
  })

  test('telemetry accepts repeated pings without mixing up payloads', async () => {
    const app = newTestApp()
    await request(app).post('/status/telemetry').send({ service: 'ci', value: 'first' })
    await request(app).post('/status/telemetry').send({ service: 'ci', value: 'second' })

    const get = await request(app).get('/status/telemetry')
    const values = get.body.reports.map((r) => r.payload.value)
    expect(values).toContain('first')
    expect(values).toContain('second')
  })
})
