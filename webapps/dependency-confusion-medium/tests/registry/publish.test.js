const request = require('supertest')
const {
  newTestApp,
  registryPkgPath,
  createRegistryAccount,
  publishVersion,
  SEED_PACKAGE_NAME,
} = require('../helpers')

describe('registry publish', () => {
  test('rejects an unauthenticated publish attempt', async () => {
    const app = newTestApp()
    const res = await publishVersion(app, null, SEED_PACKAGE_NAME, '1.0.3')

    expect(res.status).toBe(401)
  })

  test('accepts a publish from an account unrelated to the original publisher', async () => {
    const app = newTestApp()
    const account = await createRegistryAccount(app, 'mallory')
    const res = await publishVersion(app, account.body.token, SEED_PACKAGE_NAME, '1.0.3')

    expect(res.status).toBe(201)
  })

  test('the newly published version becomes dist-tags.latest', async () => {
    const app = newTestApp()
    const account = await createRegistryAccount(app, 'mallory')
    await publishVersion(app, account.body.token, SEED_PACKAGE_NAME, '1.0.3')

    const meta = await request(app).get(registryPkgPath(SEED_PACKAGE_NAME))
    expect(meta.body['dist-tags'].latest).toBe('1.0.3')
    expect(meta.body.versions['1.0.3']).toBeDefined()
    expect(meta.body.versions['1.0.2']).toBeDefined()
  })

  test('rejects a malformed body missing versions without crashing', async () => {
    const app = newTestApp()
    const account = await createRegistryAccount(app, 'mallory')
    const res = await publishVersion(app, account.body.token, SEED_PACKAGE_NAME, '1.0.3', {
      omitVersions: true,
    })

    expect(res.status).toBe(400)
  })

  test('rejects a malformed body missing _attachments without crashing', async () => {
    const app = newTestApp()
    const account = await createRegistryAccount(app, 'mallory')
    const res = await publishVersion(app, account.body.token, SEED_PACKAGE_NAME, '1.0.3', {
      omitAttachments: true,
    })

    expect(res.status).toBe(400)
  })

  test('a second publish from a different account again becomes latest', async () => {
    const app = newTestApp()
    const mallory = await createRegistryAccount(app, 'mallory')
    const eve = await createRegistryAccount(app, 'eve')

    await publishVersion(app, mallory.body.token, SEED_PACKAGE_NAME, '1.0.3')
    await publishVersion(app, eve.body.token, SEED_PACKAGE_NAME, '1.0.4')

    const meta = await request(app).get(registryPkgPath(SEED_PACKAGE_NAME))
    expect(meta.body['dist-tags'].latest).toBe('1.0.4')
  })

  test('the process stays healthy after a malformed publish (a later request still works)', async () => {
    const app = newTestApp()
    const account = await createRegistryAccount(app, 'mallory')
    await publishVersion(app, account.body.token, SEED_PACKAGE_NAME, '1.0.3', {
      omitVersions: true,
    })

    const meta = await request(app).get(registryPkgPath(SEED_PACKAGE_NAME))
    expect(meta.status).toBe(200)
  })
})
