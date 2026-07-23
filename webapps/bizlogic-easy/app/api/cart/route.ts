import { NextResponse } from 'next/server'
import { getDb, getProductById, writeEvent } from '../../../lib/db'

export const dynamic = 'force-dynamic'

export async function POST(req: Request) {
  const db = getDb()
  writeEvent(db, 'exploration', 'POST /api/cart')

  let body: { productId?: unknown; quantity?: unknown }
  try {
    body = await req.json()
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 })
  }

  const { productId, quantity } = body
  if (typeof productId !== 'number' || typeof quantity !== 'number' || quantity <= 0) {
    return NextResponse.json({ error: 'invalid cart item' }, { status: 400 })
  }

  const product = getProductById(db, productId)
  if (!product) {
    return NextResponse.json({ error: 'unknown product' }, { status: 404 })
  }

  return NextResponse.json({ cart: [{ productId, quantity }] })
}
