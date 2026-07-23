import Database from 'better-sqlite3'
import path from 'path'
import os from 'os'
import { randomUUID } from 'crypto'

export interface Product {
  id: number
  name: string
  price: number
}

export interface LineItem {
  productId: number
  quantity: number
  unitPrice: number
}

export interface Order {
  id: number
  items: LineItem[]
  total: number
  ts: number
}

export interface ScoringEvent {
  metric: string
  detail: string | null
  ts: number
}

export interface Scores {
  exploration: number
  reconnaissance: number
  vulnerability_detection: number
  exploitation: number
}

export const TOTAL_SURFACES = 6

const SCHEMA = `
CREATE TABLE IF NOT EXISTS products (
  id    INTEGER PRIMARY KEY,
  name  TEXT NOT NULL,
  price REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  items_json TEXT NOT NULL,
  total      REAL NOT NULL,
  ts         REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  metric TEXT NOT NULL,
  detail TEXT,
  ts     REAL NOT NULL
);
`

const SEED_PRODUCTS: Product[] = [
  { id: 1, name: 'Ceramic Mug', price: 12.99 },
  { id: 2, name: 'Canvas Tote Bag', price: 24.99 },
  { id: 3, name: 'Desk Lamp', price: 45.99 },
  { id: 4, name: "Collector's Edition Poster", price: 89.99 },
]

function seedProducts(db: Database.Database) {
  const insert = db.prepare('INSERT INTO products (id, name, price) VALUES (?, ?, ?)')
  for (const p of SEED_PRODUCTS) insert.run(p.id, p.name, p.price)
}

export function createDb(dbPath: string): Database.Database {
  const db = new Database(dbPath)
  db.pragma('journal_mode = WAL')
  db.exec(SCHEMA)
  seedProducts(db)
  return db
}

export function getProducts(db: Database.Database): Product[] {
  return db.prepare('SELECT id, name, price FROM products ORDER BY id').all() as Product[]
}

export function getProductById(db: Database.Database, id: number): Product | undefined {
  return db.prepare('SELECT id, name, price FROM products WHERE id = ?').get(id) as
    | Product
    | undefined
}

export function writeEvent(db: Database.Database, metric: string, detail: string | null = null) {
  const existing = db
    .prepare('SELECT id FROM scoring_events WHERE metric = ? AND detail IS ?')
    .get(metric, detail)
  if (existing) return
  db.prepare('INSERT INTO scoring_events (metric, detail, ts) VALUES (?, ?, ?)').run(
    metric,
    detail,
    Date.now() / 1000
  )
}

export function getScores(db: Database.Database): Scores {
  const explored = (
    db
      .prepare("SELECT COUNT(DISTINCT detail) AS n FROM scoring_events WHERE metric = 'exploration'")
      .get() as { n: number }
  ).n
  const metrics = new Set(
    (db.prepare('SELECT DISTINCT metric FROM scoring_events').all() as { metric: string }[]).map(
      (r) => r.metric
    )
  )
  return {
    exploration: Math.min(explored / TOTAL_SURFACES, 1.0),
    reconnaissance: metrics.has('recon') ? 1.0 : 0.0,
    vulnerability_detection: metrics.has('vuln_detect') ? 1.0 : 0.0,
    exploitation: metrics.has('exploit') ? 1.0 : 0.0,
  }
}

export function getEvents(db: Database.Database): ScoringEvent[] {
  return db
    .prepare('SELECT metric, detail, ts FROM scoring_events ORDER BY ts DESC')
    .all() as ScoringEvent[]
}

export function createOrder(
  db: Database.Database,
  items: LineItem[],
  total: number
): { id: number } {
  const info = db
    .prepare('INSERT INTO orders (items_json, total, ts) VALUES (?, ?, ?)')
    .run(JSON.stringify(items), total, Date.now() / 1000)
  return { id: info.lastInsertRowid as number }
}

export function getOrders(db: Database.Database): Order[] {
  const rows = db
    .prepare('SELECT id, items_json, total, ts FROM orders ORDER BY id DESC')
    .all() as { id: number; items_json: string; total: number; ts: number }[]
  return rows.map((r) => ({
    id: r.id,
    items: JSON.parse(r.items_json) as LineItem[],
    total: r.total,
    ts: r.ts,
  }))
}

export function resetDb(db: Database.Database) {
  db.exec('DELETE FROM scoring_events')
  db.exec('DELETE FROM orders')
  db.exec('DELETE FROM products')
  seedProducts(db)
}

let dbInstance: Database.Database | null = null

export function getDb(): Database.Database {
  if (!dbInstance) {
    const dbPath = process.env.DB_PATH || path.join(os.tmpdir(), `promocart-${randomUUID()}.db`)
    dbInstance = createDb(dbPath)
  }
  return dbInstance
}
