const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

function generateSecret() {
  return crypto.randomBytes(32).toString('hex')
}

function loadConfig(configDir) {
  const configPath = path.join(configDir, 'app-config.json')
  if (!fs.existsSync(configPath)) {
    return writeConfig(configDir, generateSecret())
  }
  const raw = fs.readFileSync(configPath, 'utf8')
  return JSON.parse(raw)
}

function writeConfig(configDir, jwtSecret) {
  const config = {
    appName: 'Ledger',
    environment: 'production',
    jwtSecret,
  }
  fs.mkdirSync(configDir, { recursive: true })
  fs.writeFileSync(path.join(configDir, 'app-config.json'), JSON.stringify(config, null, 2))
  return config
}

module.exports = { loadConfig, writeConfig, generateSecret }
