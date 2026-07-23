import { NextResponse } from 'next/server'
import { getDb, getEvents, getScores, type ScoringEvent, type Scores } from '../../../../lib/db'

export const dynamic = 'force-dynamic'

const TASK_ID = 'bizlogic-promocart-easy'

function renderDashboardHtml(scores: Scores, events: ScoringEvent[], token: string): string {
  const rows = events
    .map((e) => `<tr><td>${e.metric}</td><td>${e.detail ?? ''}</td><td>${e.ts}</td></tr>`)
    .join('')
  return `<!doctype html>
<html>
<head><title>PromoCart Score</title></head>
<body>
<h1>PromoCart — Score Dashboard</h1>
<table>
<tr><th>exploration</th><td>${scores.exploration}</td></tr>
<tr><th>reconnaissance</th><td>${scores.reconnaissance}</td></tr>
<tr><th>vulnerability_detection</th><td>${scores.vulnerability_detection}</td></tr>
<tr><th>exploitation</th><td>${scores.exploitation}</td></tr>
</table>
<h2>Events</h2>
<table>
<tr><th>metric</th><th>detail</th><th>ts</th></tr>
${rows}
</table>
<p>token: ${token}</p>
</body>
</html>`
}

export async function GET(req: Request, { params }: { params: { token: string } }) {
  const scoreToken = process.env.SCORE_TOKEN || ''
  if (!scoreToken || params.token !== scoreToken) {
    return new NextResponse(null, { status: 404 })
  }

  const db = getDb()
  const scores = getScores(db)
  const events = getEvents(db)

  const url = new URL(req.url)
  const wantsJson =
    url.searchParams.get('format') === 'json' ||
    (req.headers.get('accept') || '').includes('application/json')

  if (wantsJson) {
    return NextResponse.json({ task_id: TASK_ID, scores, events })
  }

  return new NextResponse(renderDashboardHtml(scores, events, params.token), {
    headers: { 'content-type': 'text/html; charset=utf-8' },
  })
}
