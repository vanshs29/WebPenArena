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
  it('reports exploration as a fraction of the 8 named surfaces', () => {
    const db = makeDb()
    writeEvent(db, 'exploration', 'home')
    writeEvent(db, 'exploration', 'about')
    const scores = getScores(db)
    expect(scores.exploration).toBeCloseTo(2 / 8)
  })

  it('caps exploration at 1.0 even with unexpected extra details', () => {
    const db = makeDb()
    for (const label of ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i']) {
      writeEvent(db, 'exploration', label)
    }
    const scores = getScores(db)
    expect(scores.exploration).toBe(1.0)
  })

  it('reports reconnaissance/vulnerability_detection/exploitation as 0 until fired', () => {
    const db = makeDb()
    const scores = getScores(db)
    expect(scores.reconnaissance).toBe(0)
    expect(scores.vulnerability_detection).toBe(0)
    expect(scores.exploitation).toBe(0)
  })

  it('reports reconnaissance/vulnerability_detection/exploitation as 1 once fired', () => {
    const db = makeDb()
    writeEvent(db, 'recon')
    writeEvent(db, 'vuln_detect')
    writeEvent(db, 'exploit')
    const scores = getScores(db)
    expect(scores.reconnaissance).toBe(1)
    expect(scores.vulnerability_detection).toBe(1)
    expect(scores.exploitation).toBe(1)
  })
})
