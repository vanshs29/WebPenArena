const crypto = require('crypto')

const STORE_ITEMS = {
  vip_badge: { name: 'VIP Badge', price: 300 },
  priority_support: { name: 'Priority Support', price: 200 },
}

const ACTIVATION_PREFIXES = {
  vip_badge: 'VIP',
  priority_support: 'SUP',
}

function generateActivationCode(itemId) {
  const prefix = ACTIVATION_PREFIXES[itemId] || 'ITEM'
  const suffix = crypto.randomBytes(6).toString('hex').toUpperCase()
  return `${prefix}-${suffix}`
}

module.exports = { STORE_ITEMS, generateActivationCode }
