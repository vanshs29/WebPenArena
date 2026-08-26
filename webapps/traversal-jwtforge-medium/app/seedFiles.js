const fs = require('fs')
const path = require('path')

const SOURCE_DIR = path.join(__dirname, '..', 'data')
const CANARY_CONTENT = 'LEDGER_CONFIG_DIR_MARKER\n'
const RECEIPT_FILES = ['invoice1.pdf', 'invoice2.pdf']

const receiptBuffers = {}
for (const name of RECEIPT_FILES) {
  const seedPath = path.join(SOURCE_DIR, 'uploads', name)
  receiptBuffers[name] = fs.existsSync(seedPath)
    ? fs.readFileSync(seedPath)
    : Buffer.from(`Seed receipt content for ${name}\n`)
}

function seedDataFiles(uploadsDir, configDir) {
  fs.mkdirSync(uploadsDir, { recursive: true })
  fs.mkdirSync(configDir, { recursive: true })
  for (const [name, buf] of Object.entries(receiptBuffers)) {
    fs.writeFileSync(path.join(uploadsDir, name), buf)
  }
  fs.writeFileSync(path.join(configDir, 'canary.txt'), CANARY_CONTENT)
}

module.exports = { seedDataFiles, CANARY_CONTENT }
