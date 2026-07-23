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
    return (
      <div className="confirmation">
        <h2>Order #{orderId} placed</h2>
        <p>Thank you for shopping with PromoCart.</p>
        <Link href="/" className="btn btn-secondary">
          Continue shopping
        </Link>
      </div>
    )
  }

  if (cart.length === 0) {
    return (
      <div className="empty-state">
        <p>Your cart is empty.</p>
        <Link href="/" className="back-link">
          Browse products
        </Link>
      </div>
    )
  }

  return (
    <div>
      <div className="cart-list">
        {cart.map((item) => (
          <div className="cart-row" key={item.productId}>
            <span className="cart-row-name">Product #{item.productId}</span>
            <span className="cart-row-meta">
              × {item.quantity} — ${item.unitPrice.toFixed(2)} each
            </span>
          </div>
        ))}
      </div>
      <div className="cart-summary">
        <span className="cart-total">Total: ${total.toFixed(2)}</span>
        <button className="btn" onClick={handleCheckout}>
          Checkout
        </button>
      </div>
    </div>
  )
}
