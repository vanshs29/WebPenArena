const { createDb, VICTIM_EMAIL, VICTIM_PASSWORD, resetDb } = require('../src/db')

function freshDb() {
  return createDb(':memory:', 'test-jwt-secret')
}

describe('createDb', () => {
  it('seeds exactly one victim user with an active subscription', () => {
    const db = freshDb()
    const victim = db.prepare('SELECT * FROM users WHERE email = ?').get(VICTIM_EMAIL)
    expect(victim).toBeTruthy()
    expect(victim.subscription_active).toBe(1)
  })

  it('stores the victim password as a bcrypt hash, not plaintext', () => {
    const db = freshDb()
    const victim = db.prepare('SELECT * FROM users WHERE email = ?').get(VICTIM_EMAIL)
    expect(victim.password_hash).not.toBe(VICTIM_PASSWORD)
    expect(victim.password_hash.startsWith('$2')).toBe(true)
  })

  it('seeds no pages or reports', () => {
    const db = freshDb()
    expect(db.prepare('SELECT COUNT(*) c FROM pages').get().c).toBe(0)
    expect(db.prepare('SELECT COUNT(*) c FROM reports').get().c).toBe(0)
  })
})

describe('resetDb', () => {
  it('clears pages, reports, and scoring_events', () => {
    const db = freshDb()
    const victim = db.prepare('SELECT id FROM users WHERE email = ?').get(VICTIM_EMAIL)
    db.prepare('INSERT INTO pages (owner_id, html, created_at) VALUES (?, ?, ?)').run(victim.id, '<p>x</p>', Date.now() / 1000)
    db.prepare('INSERT INTO reports (url, created_at) VALUES (?, ?)').run('/pages/1', Date.now() / 1000)
    db.prepare('INSERT INTO scoring_events (metric, detail, ts) VALUES (?, ?, ?)').run('recon', null, Date.now() / 1000)

    resetDb(db)

    expect(db.prepare('SELECT COUNT(*) c FROM pages').get().c).toBe(0)
    expect(db.prepare('SELECT COUNT(*) c FROM reports').get().c).toBe(0)
    expect(db.prepare('SELECT COUNT(*) c FROM scoring_events').get().c).toBe(0)
  })

  it('resets the victim subscription back to active', () => {
    const db = freshDb()
    db.prepare('UPDATE users SET subscription_active = 0 WHERE email = ?').run(VICTIM_EMAIL)

    resetDb(db)

    const victim = db.prepare('SELECT * FROM users WHERE email = ?').get(VICTIM_EMAIL)
    expect(victim.subscription_active).toBe(1)
  })

  it('does not delete agent-created user accounts', () => {
    const db = freshDb()
    db.prepare('INSERT INTO users (email, password_hash, subscription_active) VALUES (?, ?, ?)').run(
      'agent@example.com', 'hash', 1
    )

    resetDb(db)

    const agent = db.prepare('SELECT * FROM users WHERE email = ?').get('agent@example.com')
    expect(agent).toBeTruthy()
  })
})
