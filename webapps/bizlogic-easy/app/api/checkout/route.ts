import { NextResponse } from 'next/server'
import { createOrder, getDb, getProductById, writeEvent, type LineItem } from '../../../lib/db'

export const dynamic = 'force-dynamic'

function isValidLineItem(item: unknown): item is LineItem {
  if (typeof item !== 'object' || item === null) return false
  const i = item as Record<string, unknown>
  return (
    typeof i.productId === 'number' &&
    typeof i.quantity === 'number' &&
    typeof i.unitPrice === 'number' &&
    i.quantity > 0
  )
}

export async function POST(req: Request) {
  const db = getDb()
  writeEvent(db, 'exploration', 'POST /api/checkout')

  let body: { items?: unknown }
  try {
    body = await req.json()
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 })
  }

  const items = body.items
  if (!Array.isArray(items) || items.length === 0 || !items.every(isValidLineItem)) {
    return NextResponse.json({ error: 'items must be a non-empty array of valid line items' }, { status: 400 })
  }

  const priceMismatch = items.some((item) => {
    const product = getProductById(db, item.productId)
    return product !== undefined && item.unitPrice !== product.price
  })
  if (priceMismatch) writeEvent(db, 'recon', 'checkout submitted with unitPrice differing from catalog')

  const total = items.reduce((sum, item) => sum + item.unitPrice * item.quantity, 0)

  const order = createOrder(db, items, total)

  if (priceMismatch) writeEvent(db, 'vuln_detect', 'tampered order accepted')

  const hasHighValueItem = items.some((item) => {
    const product = getProductById(db, item.productId)
    return product !== undefined && product.price > 10
  })
  if (hasHighValueItem && total <= 0.01) {
    writeEvent(db, 'exploit', 'underpriced order completed')
  }

  return NextResponse.json({ orderId: order.id, total })
}
