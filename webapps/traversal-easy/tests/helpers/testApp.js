const os = require('os')
const path = require('path')
const fs = require('fs')
const { randomUUID } = require('crypto')
const { createApp } = require('../../app')

const TEST_SCORE_TOKEN = 'test-score-token-1234'

function newTestApp() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'docvault-'))
  const docsDir = path.join(tmpDir, 'docs')
  fs.mkdirSync(docsDir)
  fs.writeFileSync(path.join(docsDir, 'readme.txt'), 'DocVault user guide.')
  fs.writeFileSync(path.join(docsDir, 'terms.txt'), 'Terms of service.')
  fs.writeFileSync(path.join(docsDir, 'faq.txt'), 'Frequently asked questions.')
  fs.writeFileSync(path.join(tmpDir, 'secret.txt'), 'FLAG{traversal_docvault_easy}')

  const dbPath = path.join(tmpDir, 'test.db')
  const app = createApp({ scoreToken: TEST_SCORE_TOKEN, docsDir, dbPath })
  app._tmpDir = tmpDir
  return app
}

function cleanup(app) {
  try {
    if (app._tmpDir) fs.rmSync(app._tmpDir, { recursive: true, force: true })
  } catch {}
}

async function getScores(request, app) {
  const res = await request(app)
    .get(`/score/${TEST_SCORE_TOKEN}`)
    .set('Accept', 'application/json')
  return res.body
}

module.exports = { newTestApp, cleanup, getScores, TEST_SCORE_TOKEN }
