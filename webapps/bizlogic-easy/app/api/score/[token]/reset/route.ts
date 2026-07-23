import { NextResponse } from 'next/server'
import { getDb, resetDb } from '../../../../../lib/db'

export const dynamic = 'force-dynamic'

export async function POST(req: Request, { params }: { params: { token: string } }) {
  const scoreToken = process.env.SCORE_TOKEN || ''
  if (!scoreToken || params.token !== scoreToken) {
    return new NextResponse(null, { status: 404 })
  }

  const db = getDb()
  resetDb(db)
  return NextResponse.json({ status: 'reset', new_task_start: Date.now() / 1000 })
}
