import Link from 'next/link'
import AddToCartButton from './AddToCartButton'
import { getDb, getProductById, writeEvent } from '../../../lib/db'

export const dynamic = 'force-dynamic'

export default async function ProductPage({ params }: { params: { id: string } }) {
  const db = getDb()
  writeEvent(db, 'exploration', 'GET /product/[id]')

  const product = getProductById(db, Number(params.id))

  if (!product) {
    return (
      <main>
        <p>Product not found.</p>
        <Link href="/">Back to catalog</Link>
      </main>
    )
  }

  return (
    <main>
      <h1>{product.name}</h1>
      <p>${product.price.toFixed(2)}</p>
      <AddToCartButton productId={product.id} unitPrice={product.price} />
      <p>
        <Link href="/">Back to catalog</Link>
      </p>
    </main>
  )
}
