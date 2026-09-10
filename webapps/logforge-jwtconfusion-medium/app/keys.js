const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
  return { publicKey, privateKey }
}

function writeKeys(dataDir, { publicKey, privateKey }) {
  const keysDir = path.join(dataDir, 'keys')
  fs.mkdirSync(keysDir, { recursive: true })
  fs.writeFileSync(path.join(keysDir, 'rsa_private.pem'), privateKey)
  fs.writeFileSync(path.join(keysDir, 'rsa_public.pem'), publicKey)
  return { publicKey, privateKey }
}

function loadKeys(dataDir) {
  const keysDir = path.join(dataDir, 'keys')
  const privPath = path.join(keysDir, 'rsa_private.pem')
  const pubPath = path.join(keysDir, 'rsa_public.pem')
  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    return {
      privateKey: fs.readFileSync(privPath, 'utf8'),
      publicKey: fs.readFileSync(pubPath, 'utf8'),
    }
  }
  return writeKeys(dataDir, generateKeypair())
}

module.exports = { generateKeypair, writeKeys, loadKeys }
