const request = require('supertest')
const { createApp } = require('../app')

const TEST_SCORE_TOKEN = 'test-score-token-fixed'
const TEST_BILLING_KEY = 'test-billing-api-key-fixed'
const SEED_PACKAGE_NAME = '@portstone/session-utils'

function newTestApp() {
  return createApp({
    dbPath: ':memory:',
    registryDbPath: ':memory:',
    scoreToken: TEST_SCORE_TOKEN,
    internalBillingApiKey: TEST_BILLING_KEY,
  })
}

async function registerAndLogin(
  app,
  email = 'alice@test.local',
  password = 'password123',
  username = 'alice'
) {
  await request(app).post('/register').send({ username, email, password })
  const res = await request(app).post('/login').send({ email, password })
  return res.headers['set-cookie'][0].split(';')[0]
}

function registryPkgPath(pkgName) {
  return `/registry/${pkgName.replace('/', '%2f')}`
}

async function createRegistryAccount(app, username) {
  const res = await request(app)
    .put(`/registry/-/user/org.couchdb.user/${username}`)
    .send({ name: username, password: 'pw-12345', type: 'user', roles: [] })
  return res
}

function buildAttachment(tarballBuffer, filename) {
  return {
    [filename]: {
      content_type: 'application/octet-stream',
      data: tarballBuffer.toString('base64'),
      length: tarballBuffer.length,
    },
  }
}

async function publishVersion(app, token, pkgName, version, options = {}) {
  const tarballBuffer = options.tarballBuffer || Buffer.from(`fake-tarball-bytes-${version}`)
  const shortName = pkgName.split('/').pop()
  const filename = `${shortName}-${version}.tgz`

  const body = {
    name: pkgName,
    versions: {
      [version]: { name: pkgName, version, ...(options.manifestExtra || {}) },
    },
    ...(options.omitAttachments ? {} : { _attachments: buildAttachment(tarballBuffer, filename) }),
  }
  if (options.omitVersions) delete body.versions

  const req = request(app).put(registryPkgPath(pkgName))
  if (token) req.set('Authorization', `Bearer ${token}`)
  return req.send(body)
}

module.exports = {
  newTestApp,
  registerAndLogin,
  registryPkgPath,
  createRegistryAccount,
  publishVersion,
  buildAttachment,
  TEST_SCORE_TOKEN,
  TEST_BILLING_KEY,
  SEED_PACKAGE_NAME,
}
