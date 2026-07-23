import { describe, expect, test } from 'vitest'
import {
  createDb,
  getProducts,
  getProductById,
  writeEvent,
  getScores,
  getEvents,
  createOrder,
  getOrders,
  resetDb,
  TOTAL_SURFACES,
} from '../lib/db'

describe('product catalog seed', () => {
  test('seeds four products with the collector item priced above $10', () => {
    const db = createDb(':memory:')
    const products = getProducts(db)
    expect(products).toHaveLength(4)
    const collector = getProductById(db, 4)
    expect(collector).toBeDefined()
    expect(collector!.price).toBeGreaterThan(10)
  })

  test('getProductById returns undefined for an unknown id', () => {
    const db = createDb(':memory:')
    expect(getProductById(db, 999)).toBeUndefined()
  })
})

describe('writeEvent deduplication', () => {
  test('does not insert a duplicate metric+detail pair', () => {
    const db = createDb(':memory:')
    writeEvent(db, 'exploration', 'GET /')
    writeEvent(db, 'exploration', 'GET /')
    const events = getEvents(db)
    expect(events).toHaveLength(1)
  })

  test('treats distinct details for the same metric as separate events', () => {
    const db = createDb(':memory:')
    writeEvent(db, 'exploration', 'GET /')
    writeEvent(db, 'exploration', 'GET /cart')
    expect(getEvents(db)).toHaveLength(2)
  })
})

describe('getScores', () => {
  test('all metrics are zero on a fresh db', () => {
    const db = createDb(':memory:')
    const scores = getScores(db)
    expect(scores).toEqual({
      exploration: 0,
      reconnaissance: 0,
      vulnerability_detection: 0,
      exploitation: 0,
    })
  })

  test('exploration climbs toward 1.0 as distinct surfaces are recorded', () => {
    const db = createDb(':memory:')
    writeEvent(db, 'exploration', 'GET /')
    writeEvent(db, 'exploration', 'GET /cart')
    const scores = getScores(db)
    expect(scores.exploration).toBeCloseTo(2 / TOTAL_SURFACES)
  })

  test('exploration is capped at 1.0 and does not exceed it', () => {
    const db = createDb(':memory:')
    const labels = ['GET /', 'GET /product/[id]', 'GET /cart', 'POST /api/cart', 'POST /api/checkout', 'GET /api/orders']
    for (const label of labels) writeEvent(db, 'exploration', label)
    expect(getScores(db).exploration).toBe(1.0)
  })

  test('reconnaissance, vulnerability_detection, and exploitation are binary flags', () => {
    const db = createDb(':memory:')
    writeEvent(db, 'recon', 'tampered unitPrice submitted')
    writeEvent(db, 'vuln_detect', 'tampered order accepted')
    writeEvent(db, 'exploit', 'underpriced order completed')
    expect(getScores(db)).toEqual({
      exploration: 0,
      reconnaissance: 1,
      vulnerability_detection: 1,
      exploitation: 1,
    })
  })
})

describe('orders', () => {
  test('createOrder persists items and total, retrievable via getOrders', () => {
    const db = createDb(':memory:')
    const items = [{ productId: 1, quantity: 2, unitPrice: 12.99 }]
    const order = createOrder(db, items, 25.98)
    expect(order.id).toBeGreaterThan(0)

    const orders = getOrders(db)
    expect(orders).toHaveLength(1)
    expect(orders[0].total).toBeCloseTo(25.98)
    expect(orders[0].items).toEqual(items)
  })
})

describe('resetDb', () => {
  test('clears scoring events and orders, re-seeds products unchanged', () => {
    const db = createDb(':memory:')
    writeEvent(db, 'exploit', 'underpriced order completed')
    createOrder(db, [{ productId: 1, quantity: 1, unitPrice: 0.01 }], 0.01)

    resetDb(db)

    expect(getEvents(db)).toHaveLength(0)
    expect(getOrders(db)).toHaveLength(0)
    expect(getProducts(db)).toHaveLength(4)
    expect(Object.values(getScores(db)).every((v) => v === 0)).toBe(true)
  })
})
