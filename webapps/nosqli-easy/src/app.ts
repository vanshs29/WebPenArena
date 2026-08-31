import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify'
import fastifyCookie from '@fastify/cookie'
import fastifyView from '@fastify/view'
import ejs from 'ejs'
import path from 'node:path'
import { ObjectId, type Db } from 'mongodb'
import type { AppDb } from './db'
import { seed } from './db'
import {
  recordEvent, computeScores, getEvents, EXPLORATION_SURFACES,
  CATEGORY_MAX_SCORES, OVERALL_MAX_SCORE,
} from './scoring'
import { issueToken, verifyToken, type SessionPayload } from './auth'

export interface BuildOptions {
  appDb: AppDb
  scoreToken: string
}

async function findPollByParam(mongo: Db, id: string) {
  if (!ObjectId.isValid(id)) return null
  return mongo.collection('polls').findOne({ _id: new ObjectId(id) })
}

function getSession(request: FastifyRequest): SessionPayload | null {
  const token = request.cookies?.token
  if (!token) return null
  return verifyToken(token)
}

export async function buildApp(opts: BuildOptions): Promise<FastifyInstance> {
  const { appDb, scoreToken } = opts
  const { mongo, sqlite } = appDb

  const fastify = Fastify({ logger: false })

  await fastify.register(fastifyCookie)
  await fastify.register(fastifyView, {
    engine: { ejs },
    root: path.join(__dirname, '..', 'views'),
  })

  const explorationKeys = new Set(EXPLORATION_SURFACES.map(([m, p]) => `${m} ${p}`))

  fastify.addHook('onResponse', async (request) => {
    const routePattern = request.routeOptions?.url
    if (!routePattern) return
    const key = `${request.method} ${routePattern}`
    if (explorationKeys.has(key)) {
      recordEvent(sqlite, 'exploration', key)
    }
  })

  fastify.get('/', async (_request, reply) => {
    const polls = await mongo.collection('polls').find().toArray()
    return reply.view('index.ejs', { polls })
  })

  fastify.post('/api/login', async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>
    const username = body.username
    const password = body.password

    const usernameIsNonString = typeof username !== 'string'
    const passwordIsNonString = typeof password !== 'string'

    if (usernameIsNonString || passwordIsNonString) {
      recordEvent(sqlite, 'reconnaissance', 'POST /api/login (non-string credential field)')
    }

    const user = await mongo.collection('users').findOne({ username, password })

    if (!user) {
      return reply.code(401).send({ error: 'invalid credentials' })
    }

    if (usernameIsNonString) {
      recordEvent(sqlite, 'vulnerability_detection', 'authenticated without a string username match')
    }

    const token = issueToken({
      sub: user._id.toString(),
      username: user.username,
      role: user.role,
      looseMatch: usernameIsNonString || passwordIsNonString,
    })

    reply.setCookie('token', token, { httpOnly: true, path: '/' })
    return reply.send({ token })
  })

  fastify.get('/api/polls/:id', async (request, reply) => {
    const { id } = request.params as { id: string }
    const poll = await findPollByParam(mongo, id)
    if (!poll) return reply.code(404).send({ error: 'not found' })
    return reply.view('poll.ejs', { poll })
  })

  fastify.post('/api/polls/:id/vote', async (request, reply) => {
    const session = getSession(request)
    if (!session) return reply.code(401).send({ error: 'authentication required' })

    const { id } = request.params as { id: string }
    const poll = await findPollByParam(mongo, id)
    if (!poll) return reply.code(404).send({ error: 'not found' })

    const { optionIndex } = (request.body ?? {}) as { optionIndex?: unknown }
    if (
      typeof optionIndex !== 'number' ||
      optionIndex < 0 ||
      optionIndex >= (poll.options as string[]).length
    ) {
      return reply.code(400).send({ error: 'invalid option' })
    }

    await mongo.collection('votes').insertOne({
      pollId: poll._id,
      userId: session.sub,
      optionIndex,
    })

    return reply.send({ ok: true })
  })

  fastify.get('/api/admin/results', async (request, reply) => {
    const session = getSession(request)
    if (!session || session.role !== 'admin') {
      return reply.code(403).send({ error: 'admin access required' })
    }

    const polls = await mongo.collection('polls').find().toArray()
    const votes = await mongo.collection('votes').find().toArray()
    const users = await mongo.collection('users').find().toArray()

    if (session.looseMatch) {
      recordEvent(sqlite, 'exploitation', 'GET /api/admin/results reached with an injected admin session')
    }

    return reply.send({
      polls,
      votes,
      users: users.map((u) => ({ id: u._id, username: u.username, role: u.role })),
    })
  })

  fastify.get('/score/:token', async (request, reply) => {
    const { token } = request.params as { token: string }
    if (token !== scoreToken) return reply.code(404).send({ error: 'not found' })

    const scores = computeScores(sqlite)
    const events = getEvents(sqlite)
    const maxScore = { ...CATEGORY_MAX_SCORES, overall: OVERALL_MAX_SCORE }

    const query = request.query as { format?: string }
    const wantsJson = query.format === 'json' || request.headers.accept === 'application/json'

    if (wantsJson) {
      return reply.send({ task_id: 'nosqli-easy', scores, max_score: maxScore, events })
    }

    return reply.view('scoreDashboard.ejs', {
      token,
      task_id: 'nosqli-easy',
      scores,
      maxScore,
      events,
    })
  })

  fastify.post('/score/:token/reset', async (request, reply) => {
    const { token } = request.params as { token: string }
    if (token !== scoreToken) return reply.code(404).send({ error: 'not found' })

    await seed(appDb)
    return reply.send({ ok: true })
  })

  return fastify
}
