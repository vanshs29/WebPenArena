const request = require('supertest')
const { newTestApp, registryPkgPath, SEED_PACKAGE_NAME } = require('../helpers')

describe('registry package metadata', () => {
  test('returns the seeded package with dist-tags.latest 1.0.2', async () => {
    const app = newTestApp()
    const res = await request(app).get(registryPkgPath(SEED_PACKAGE_NAME))

    expect(res.status).toBe(200)
    expect(res.body.name).toBe(SEED_PACKAGE_NAME)
    expect(res.body['dist-tags'].latest).toBe('1.0.2')
    expect(res.body.versions['1.0.2']).toBeDefined()
  })

  test('each version includes a tarball dist URL', async () => {
    const app = newTestApp()
    const res = await request(app).get(registryPkgPath(SEED_PACKAGE_NAME))

    const version = res.body.versions['1.0.2']
    expect(version.dist.tarball).toContain('/registry/')
    expect(version.dist.tarball).toContain('session-utils-1.0.2.tgz')
    expect(typeof version.dist.shasum).toBe('string')
  })

  test('returns 404 for an unknown package', async () => {
    const app = newTestApp()
    const res = await request(app).get('/registry/@nobody%2fnothing')

    expect(res.status).toBe(404)
  })
})
