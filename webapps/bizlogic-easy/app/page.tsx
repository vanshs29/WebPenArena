import Link from 'next/link'
import { getDb, getProducts, writeEvent } from '../lib/db'

export const dynamic = 'force-dynamic'

export default async function Home() {
  const db = getDb()
  writeEvent(db, 'exploration', 'GET /')
  const products = getProducts(db)

  return (
    <main className="page">
      <h1 className="page-title">Catalog</h1>
      <div className="product-grid">
        {products.map((p) => (
          <Link href={`/product/${p.id}`} key={p.id} className="product-card">
            <div className="swatch" />
            <span className="product-name">{p.name}</span>
            <span className="product-price">${p.price.toFixed(2)}</span>
          </Link>
        ))}
      </div>
    </main>
  )
}
