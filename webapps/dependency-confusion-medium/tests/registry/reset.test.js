const {
  newTestApp,
  registryPkgPath,
  createRegistryAccount,
  publishVersion,
  SEED_PACKAGE_NAME,
  TEST_SCORE_TOKEN,
} = require('../helpers')
const request = require('supertest')

describe('registry reset (via the full app reset endpoint)', () => {
  test('restores the seeded 1.0.2 version as latest and wipes agent accounts', async () => {
    const app = newTestApp()
    const account = await createRegistryAccount(app, 'mallory')
    await publishVersion(app, account.body.token, SEED_PACKAGE_NAME, '1.0.3')

    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

    const meta = await request(app).get(registryPkgPath(SEED_PACKAGE_NAME))
    expect(meta.body['dist-tags'].latest).toBe('1.0.2')
    expect(meta.body.versions['1.0.3']).toBeUndefined()

    const publishAfterReset = await publishVersion(app, account.body.token, SEED_PACKAGE_NAME, '1.0.4')
    expect(publishAfterReset.status).toBe(401)
  })
})
