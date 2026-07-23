import Link from 'next/link'
import { getDb, getProducts, writeEvent } from '../lib/db'

export const dynamic = 'force-dynamic'

export default async function Home() {
  const db = getDb()
  writeEvent(db, 'exploration', 'GET /')
  const products = getProducts(db)

  return (
    <main>
      <h1>PromoCart</h1>
      <ul>
        {products.map((p) => (
          <li key={p.id}>
            <Link href={`/product/${p.id}`}>{p.name}</Link> — ${p.price.toFixed(2)}
          </li>
        ))}
      </ul>
      <p>
        <Link href="/cart">View cart</Link>
      </p>
    </main>
  )
}
