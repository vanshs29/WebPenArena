import { NextResponse } from 'next/server'
import { getDb, getEvents, getScores, type ScoringEvent, type Scores } from '../../../lib/db'

export const dynamic = 'force-dynamic'

const TASK_ID = 'bizlogic-promocart-easy'

function renderDashboardHtml(scores: Scores, events: ScoringEvent[], token: string): string {
  const metricRows = (Object.keys(scores) as (keyof Scores)[])
    .map((key) => {
      const value = scores[key]
      const pct = Math.round(value * 100)
      return `<tr>
        <th>${key.replace(/_/g, ' ')}</th>
        <td class="bar-cell"><div class="bar"><div class="bar-fill" style="width:${pct}%"></div></div></td>
        <td class="value">${value.toFixed(2)}</td>
      </tr>`
    })
    .join('')

  const eventRows = events
    .map(
      (e) =>
        `<tr><td>${e.metric}</td><td>${e.detail ?? ''}</td><td>${new Date(e.ts * 1000).toLocaleString()}</td></tr>`
    )
    .join('')

  return `<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>PromoCart — Score</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 760px; margin: 3rem auto; padding: 0 1.5rem; color: #1c1c1e; background: #fafafa; }
  h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
  .token { color: #6b7280; font-size: 0.85rem; margin-bottom: 2rem; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
  th, td { text-align: left; padding: 0.65rem 0.9rem; border-bottom: 1px solid #eee; font-size: 0.9rem; }
  tr:last-child th, tr:last-child td { border-bottom: none; }
  th { font-weight: 600; text-transform: capitalize; }
  .bar-cell { width: 45%; }
  .bar { background: #e5e7eb; border-radius: 999px; height: 8px; overflow: hidden; }
  .bar-fill { background: #2563eb; height: 100%; border-radius: 999px; }
  .value { text-align: right; font-variant-numeric: tabular-nums; color: #374151; }
  h2 { font-size: 1.1rem; margin: 2rem 0 0.75rem; }
</style>
</head>
<body>
<h1>PromoCart — Score Dashboard</h1>
<p class="token">token: ${token}</p>
<table>
<tbody>${metricRows}</tbody>
</table>
<h2>Events</h2>
<table>
<tr><th>metric</th><th>detail</th><th>time</th></tr>
${eventRows || '<tr><td colspan="3">No events yet.</td></tr>'}
</table>
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
