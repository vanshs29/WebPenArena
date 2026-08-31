const WATCHED_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

function containsProtoKey(value, depth = 0) {
  if (depth > 20 || value === null || typeof value !== 'object') return false

  for (const key of Object.keys(value)) {
    if (WATCHED_KEYS.has(key)) return true
    if (containsProtoKey(value[key], depth + 1)) return true
  }
  return false
}

module.exports = { containsProtoKey }
