'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { readCart, clearCart, type ClientCartItem } from '../../lib/cartClient'

export default function CartClient() {
  const [cart, setCart] = useState<ClientCartItem[]>([])
  const [orderId, setOrderId] = useState<number | null>(null)

  useEffect(() => {
    setCart(readCart())
  }, [])

  const total = cart.reduce((sum, i) => sum + i.unitPrice * i.quantity, 0)

  async function handleCheckout() {
    const res = await fetch('/api/checkout', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ items: cart }),
    })
    const body = await res.json()
    setOrderId(body.orderId)
    clearCart()
    setCart([])
  }

  if (orderId !== null) {
    return <p>Order #{orderId} placed. Thank you!</p>
  }

  if (cart.length === 0) {
    return (
      <p>
        Your cart is empty. <Link href="/">Browse products</Link>
      </p>
    )
  }

  return (
    <div>
      <ul>
        {cart.map((item) => (
          <li key={item.productId}>
            Product #{item.productId} × {item.quantity} — ${item.unitPrice.toFixed(2)} each
          </li>
        ))}
      </ul>
      <p>Total: ${total.toFixed(2)}</p>
      <button onClick={handleCheckout}>Checkout</button>
    </div>
  )
}
