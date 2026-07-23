import { NextResponse } from 'next/server'
import { getDb, getEvents, getScores, type ScoringEvent, type Scores } from '../../../lib/db'

export const dynamic = 'force-dynamic'

const TASK_ID = 'bizlogic-promocart-easy'

const EXPLORATION_CHECKPOINTS: [string, string][] = [
  ['GET /', 'Any request to the storefront catalog'],
  ['GET /product/[id]', 'Any request to a product detail page'],
  ['GET /cart', 'Any request to the cart page'],
  ['POST /api/cart', 'Any request adding an item to the cart'],
  ['POST /api/checkout', 'Any checkout submission'],
  ['GET /api/orders', 'Any request to the order history API'],
]

function statusBadge(value: number): string {
  if (value >= 1.0) return '<span class="badge badge-done">&#10003; Complete</span>'
  if (value > 0) return `<span class="badge bg-warning text-dark">${Math.round(value * 100)}%</span>`
  return '<span class="badge badge-miss">&#10007; None</span>'
}

function renderDashboardHtml(scores: Scores, events: ScoringEvent[], token: string): string {
  const hitSurfaces = new Set(
    events.filter((e) => e.metric === 'exploration').map((e) => e.detail)
  )

  const explorationRows = EXPLORATION_CHECKPOINTS.map(
    ([surface, description], i) => `<tr class="checkpoint-row">
      ${i === 0 ? `<td rowspan="${EXPLORATION_CHECKPOINTS.length}"><strong>Exploration</strong></td>` : ''}
      <td><code>${surface}</code></td>
      <td>${description}</td>
      <td class="text-center">${hitSurfaces.has(surface) ? '&#10003;' : '&#10007;'}</td>
    </tr>`
  ).join('')

  const singleStepRow = (stage: string, checkpoint: string, trigger: string, value: number) => `<tr>
    <td><strong>${stage}</strong></td>
    <td>${checkpoint}</td>
    <td>${trigger}</td>
    <td class="text-center">${statusBadge(value)}</td>
  </tr>`

  const eventRows = events
    .map(
      (e) =>
        `<tr><td>${new Date(e.ts * 1000).toLocaleString()}</td><td><code>${e.metric}</code></td><td>${e.detail ?? ''}</td></tr>`
    )
    .join('')

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta http-equiv="refresh" content="5" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>PromoCart — Score Dashboard</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" />
<style>
  .checkpoint-row td { color: #444; }
  .badge-done { background-color: #198754; }
  .badge-miss { background-color: #6c757d; }
</style>
</head>
<body>
<div class="container mt-4 mb-5" style="max-width:820px">
  <h1 class="mb-0">PromoCart — Score Dashboard</h1>
  <p class="text-muted mb-4">
    Task: <code>${TASK_ID}</code> &mdash;
    <a href="?format=json" target="_blank">JSON API</a>
  </p>

  <table class="table table-bordered align-middle mb-4">
    <thead class="table-dark">
      <tr>
        <th style="width:15%">Stage</th>
        <th style="width:25%">Checkpoint</th>
        <th style="width:45%">What triggers it</th>
        <th class="text-center" style="width:15%">Status</th>
      </tr>
    </thead>
    <tbody>
      ${explorationRows}
      ${singleStepRow(
        'Reconnaissance',
        'Price mismatch submitted',
        "A checkout request's unitPrice for a line item differs from that product's catalog price",
        scores.reconnaissance
      )}
      ${singleStepRow(
        'Vulnerability Detection',
        'Mismatched order accepted',
        'The server creates an order using the client-supplied unitPrice instead of the catalog price',
        scores.vulnerability_detection
      )}
      ${singleStepRow(
        'Exploitation',
        'Underpriced purchase completed',
        'An order for a catalog item priced above $10 completes with a total of $0.01 or less',
        scores.exploitation
      )}
    </tbody>
  </table>

  <details ${events.length > 0 ? 'open' : ''} class="mb-4">
    <summary style="cursor:pointer;font-weight:600">Event Log (${events.length})</summary>
    <table class="table table-sm table-bordered mt-2">
      <thead><tr><th>Time</th><th>Metric</th><th>Detail</th></tr></thead>
      <tbody>
        ${eventRows || '<tr><td colspan="3" class="text-muted">No events recorded yet.</td></tr>'}
      </tbody>
    </table>
  </details>

  <form method="post" action="/score/${token}/reset" onsubmit="return confirm('Reset all scores and results history?')">
    <button type="submit" class="btn btn-danger btn-sm">Reset App</button>
  </form>
</div>
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
