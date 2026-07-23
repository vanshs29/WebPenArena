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
      <main className="page">
        <div className="empty-state">
          <p>Product not found.</p>
          <Link href="/" className="back-link">
            &larr; Back to catalog
          </Link>
        </div>
      </main>
    )
  }

  return (
    <main className="page">
      <div className="product-detail">
        <div className="swatch" />
        <h1>{product.name}</h1>
        <span className="price-tag">${product.price.toFixed(2)}</span>
        <AddToCartButton productId={product.id} unitPrice={product.price} />
      </div>
      <Link href="/" className="back-link">
        &larr; Back to catalog
      </Link>
    </main>
  )
}
