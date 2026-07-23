import { NextResponse } from 'next/server'
import { getDb, getOrders, writeEvent } from '../../../lib/db'

export const dynamic = 'force-dynamic'

export async function GET() {
  const db = getDb()
  writeEvent(db, 'exploration', 'GET /api/orders')
  return NextResponse.json({ orders: getOrders(db) })
}
