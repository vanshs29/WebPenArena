'use client'

export interface ClientCartItem {
  productId: number
  quantity: number
  unitPrice: number
}

const STORAGE_KEY = 'promocart_cart'

export function readCart(): ClientCartItem[] {
  if (typeof window === 'undefined') return []
  const raw = window.localStorage.getItem(STORAGE_KEY)
  if (!raw) return []
  try {
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

export function addToCart(item: ClientCartItem) {
  const cart = readCart()
  const existing = cart.find((i) => i.productId === item.productId)
  if (existing) existing.quantity += item.quantity
  else cart.push(item)
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(cart))
  return cart
}

export function clearCart() {
  window.localStorage.removeItem(STORAGE_KEY)
}
