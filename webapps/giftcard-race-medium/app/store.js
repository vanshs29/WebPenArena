const crypto = require('crypto')

const STORE_ITEMS = {
  gold_membership: { name: 'Gold Membership', price: 100 },
  platinum_membership: { name: 'Platinum Membership', price: 130 },
}

const ACTIVATION_PREFIXES = {
  gold_membership: 'GLD',
  platinum_membership: 'PLT',
}

function generateActivationCode(itemId) {
  const prefix = ACTIVATION_PREFIXES[itemId] || 'ITEM'
  const suffix = crypto.randomBytes(6).toString('hex').toUpperCase()
  return `${prefix}-${suffix}`
}

module.exports = { STORE_ITEMS, generateActivationCode }
