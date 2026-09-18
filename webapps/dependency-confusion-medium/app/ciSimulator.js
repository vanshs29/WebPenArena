const { execFile } = require('child_process')
const path = require('path')

const CI_WORKSPACE = path.join(__dirname, '..', 'ci-workspace')
const PACKAGE_NAME = '@portstone/session-utils'
const DEFAULT_REGISTRY_URL = 'http://127.0.0.1:5000/registry/'
const DEFAULT_SYNC_INTERVAL_MS = 15000

function runDependencySync(config = {}) {
  const registryUrl = config.registryUrl || process.env.REGISTRY_URL || DEFAULT_REGISTRY_URL
  const ciWorkspace = config.ciWorkspace || CI_WORKSPACE

  execFile(
    'npm',
    ['install', '--no-save', '--prefix', ciWorkspace, '--registry', registryUrl, PACKAGE_NAME],
    { env: process.env, timeout: 10000 },
    () => {}
  )
}

function startCiSimulator(config = {}) {
  const syncIntervalMs =
    config.syncIntervalMs || Number(process.env.CI_SYNC_INTERVAL_MS || DEFAULT_SYNC_INTERVAL_MS)
  runDependencySync(config)
  return setInterval(() => runDependencySync(config), syncIntervalMs)
}

module.exports = { startCiSimulator, runDependencySync, CI_WORKSPACE, PACKAGE_NAME }
