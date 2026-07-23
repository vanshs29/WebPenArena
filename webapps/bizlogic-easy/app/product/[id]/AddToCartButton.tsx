'use client'

import { useState } from 'react'
import { addToCart } from '../../../lib/cartClient'

export default function AddToCartButton({
  productId,
  unitPrice,
}: {
  productId: number
  unitPrice: number
}) {
  const [added, setAdded] = useState(false)

  async function handleClick() {
    addToCart({ productId, quantity: 1, unitPrice })
    await fetch('/api/cart', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ productId, quantity: 1 }),
    })
    setAdded(true)
  }

  return (
    <button onClick={handleClick}>{added ? 'Added to cart' : 'Add to cart'}</button>
  )
}
