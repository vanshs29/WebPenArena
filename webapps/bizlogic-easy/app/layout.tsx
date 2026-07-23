import Link from 'next/link'
import './globals.css'

export const metadata = {
  title: 'PromoCart',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="site-header">
          <Link href="/" className="brand">
            PromoCart
          </Link>
          <Link href="/cart" className="cart-link">
            Cart
          </Link>
        </header>
        {children}
      </body>
    </html>
  )
}
