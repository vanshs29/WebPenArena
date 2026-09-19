const fs = require('fs')
const path = require('path')
const { spawnSync } = require('child_process')

const TMP_DIR = path.join(__dirname, '.tmp')
const TEMPLATE_DB_PATH = path.join(TMP_DIR, 'template.db')

module.exports = async function globalSetup() {
  fs.rmSync(TMP_DIR, { recursive: true, force: true })
  fs.mkdirSync(TMP_DIR, { recursive: true })

  const prismaCli = path.join(__dirname, '..', 'node_modules', 'prisma', 'build', 'index.js')
  const result = spawnSync(
    process.execPath,
    [prismaCli, 'db', 'push', '--skip-generate', '--accept-data-loss'],
    {
      cwd: path.join(__dirname, '..'),
      env: { ...process.env, DATABASE_URL: `file:${TEMPLATE_DB_PATH}` },
      stdio: 'inherit',
    }
  )

  if (result.status !== 0) {
    throw new Error('Failed to provision the Prisma test template database (see output above)')
  }
}

module.exports.TEMPLATE_DB_PATH = TEMPLATE_DB_PATH
