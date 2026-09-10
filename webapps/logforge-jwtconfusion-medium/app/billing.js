const crypto = require('crypto')

function generateBillingArtifact() {
  const suffix = crypto.randomBytes(24).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 24)
  return `sk_live_51${suffix}`
}

module.exports = { generateBillingArtifact }
