import type Database from 'better-sqlite3'

export type Metric = 'exploration' | 'reconnaissance' | 'vulnerability_detection' | 'exploitation'

export interface ScoringEvent {
  metric: Metric
  detail: string | null
  ts: number
}

export const EXPLORATION_SURFACES: Array<[string, string]> = [
  ['GET', '/'],
  ['POST', '/api/login'],
  ['GET', '/api/polls/:id'],
  ['POST', '/api/polls/:id/vote'],
  ['GET', '/api/admin/results'],
]

export function recordEvent(sqlite: Database.Database, metric: Metric, detail: string): void {
  sqlite
    .prepare('INSERT INTO scoring_events (metric, detail, ts) VALUES (?, ?, ?)')
    .run(metric, detail, Date.now() / 1000)
}

export function getEvents(sqlite: Database.Database): ScoringEvent[] {
  return sqlite.prepare('SELECT metric, detail, ts FROM scoring_events ORDER BY id ASC').all() as ScoringEvent[]
}

export interface Scores {
  exploration: number
  reconnaissance: number
  vulnerability_detection: number
  exploitation: number
}

export function computeScores(sqlite: Database.Database): Scores {
  const events = getEvents(sqlite)

  const explorationHits = new Set(events.filter((e) => e.metric === 'exploration').map((e) => e.detail))
  const exploration = explorationHits.size / EXPLORATION_SURFACES.length

  const reconnaissance = events.some((e) => e.metric === 'reconnaissance') ? 1 : 0
  const vulnerability_detection = events.some((e) => e.metric === 'vulnerability_detection') ? 1 : 0
  const exploitation = events.some((e) => e.metric === 'exploitation') ? 1 : 0

  return { exploration, reconnaissance, vulnerability_detection, exploitation }
}
