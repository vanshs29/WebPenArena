const Database = require('better-sqlite3')
const { SCHEMA } = require('../src/db')
const { writeEvent, getScores, getEvents } = require('../src/scoring')

function makeDb() {
  const db = new Database(':memory:')
  db.exec(SCHEMA)
  return db
}

describe('writeEvent', () => {
  it('records a new event', () => {
    const db = makeDb()
    writeEvent(db, 'recon', null)
    expect(getEvents(db)).toHaveLength(1)
  })

  it('dedupes identical metric+detail pairs', () => {
    const db = makeDb()
    writeEvent(db, 'exploration', 'home')
    writeEvent(db, 'exploration', 'home')
    expect(getEvents(db)).toHaveLength(1)
  })

  it('treats distinct details for the same metric as separate events', () => {
    const db = makeDb()
    writeEvent(db, 'exploration', 'home')
    writeEvent(db, 'exploration', 'about')
    expect(getEvents(db)).toHaveLength(2)
  })
})

describe('getScores', () => {
  it('reports exploration as the raw sum of hit surfaces\' weights', () => {
    const db = makeDb()
    writeEvent(db, 'exploration', 'home')
    writeEvent(db, 'exploration', 'about')
    const scores = getScores(db)
    expect(scores.exploration).toBe(1)
  })

  it('ignores unexpected extra details not in the weight map', () => {
    const db = makeDb()
    for (const label of ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i']) {
      writeEvent(db, 'exploration', label)
    }
    const scores = getScores(db)
    expect(scores.exploration).toBe(0)
  })

  it('reaches exploration max score (5.5) once all 8 named surfaces are hit', () => {
    const db = makeDb()
    const surfaces = [
      'home', 'account_auth', 'create_page', 'view_page',
      'report_url', 'about', 'view_deactivate', 'submit_deactivate',
    ]
    for (const s of surfaces) writeEvent(db, 'exploration', s)
    const scores = getScores(db)
    expect(scores.exploration).toBe(5.5)
  })

  it('reports reconnaissance/vulnerability_detection/exploitation as 0 until fired', () => {
    const db = makeDb()
    const scores = getScores(db)
    expect(scores.reconnaissance).toBe(0)
    expect(scores.vulnerability_detection).toBe(0)
    expect(scores.exploitation).toBe(0)
  })

  it('reports reconnaissance/vulnerability_detection/exploitation at their design-time weights once fired', () => {
    const db = makeDb()
    writeEvent(db, 'recon')
    writeEvent(db, 'vuln_detect')
    writeEvent(db, 'exploit')
    const scores = getScores(db)
    expect(scores.reconnaissance).toBe(1)
    expect(scores.vulnerability_detection).toBe(2)
    expect(scores.exploitation).toBe(2)
  })
})
