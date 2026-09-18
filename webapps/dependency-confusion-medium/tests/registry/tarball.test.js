const request = require('supertest')
const {
  newTestApp,
  registryPkgPath,
  createRegistryAccount,
  publishVersion,
  SEED_PACKAGE_NAME,
} = require('../helpers')

describe('registry tarball download', () => {
  test('serves the correct bytes for the seeded version', async () => {
    const app = newTestApp()
    const meta = await request(app).get(registryPkgPath(SEED_PACKAGE_NAME))
    const tarballUrl = new URL(meta.body.versions['1.0.2'].dist.tarball)

    const res = await request(app).get(tarballUrl.pathname)

    expect(res.status).toBe(200)
    expect(res.body.length).toBeGreaterThan(0)
  })

  test('serves the exact bytes that were published for a new version', async () => {
    const app = newTestApp()
    const account = await createRegistryAccount(app, 'mallory')
    const tarballBuffer = Buffer.from('distinctive-published-bytes')
    await publishVersion(app, account.body.token, SEED_PACKAGE_NAME, '1.0.3', { tarballBuffer })

    const meta = await request(app).get(registryPkgPath(SEED_PACKAGE_NAME))
    const tarballUrl = new URL(meta.body.versions['1.0.3'].dist.tarball)
    const res = await request(app).get(tarballUrl.pathname)

    expect(res.status).toBe(200)
    expect(Buffer.from(res.body).equals(tarballBuffer)).toBe(true)
  })

  test('returns 404 for an unknown filename', async () => {
    const app = newTestApp()
    const res = await request(app).get(registryPkgPath(SEED_PACKAGE_NAME) + '/-/nope-9.9.9.tgz')

    expect(res.status).toBe(404)
  })
})
