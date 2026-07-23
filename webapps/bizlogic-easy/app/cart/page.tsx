import { getDb, writeEvent } from '../../lib/db'
import CartClient from './CartClient'

export const dynamic = 'force-dynamic'

export default async function CartPage() {
  writeEvent(getDb(), 'exploration', 'GET /cart')
  return (
    <main>
      <h1>Your Cart</h1>
      <CartClient />
    </main>
  )
}
