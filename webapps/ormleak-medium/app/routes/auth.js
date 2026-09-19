const express = require('express')
const { issueSession, generateResetToken } = require('../auth')
const { writeEvent } = require('../scoring')
const { asyncHandler } = require('../asyncHandler')
const { ADMIN_EMAIL } = require('../constants')

const router = express.Router()

router.get('/login', (req, res) => res.render('login', { error: null }))

router.get('/register', (req, res) => res.render('register', { error: null }))

router.post(
  '/login',
  asyncHandler(async (req, res) => {
    const prisma = req.app.locals.prisma
    const { email, password } = req.body || {}
    if (typeof email !== 'string' || !email || typeof password !== 'string' || !password) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }

    const user = await prisma.user.findUnique({ where: { email } })
    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }

    if (user.email === ADMIN_EMAIL) {
      await writeEvent(prisma, 'exploit_admin_account_compromised')
    }

    const priorBypass = await prisma.scoringEvent.findFirst({
      where: { metric: 'vuln_detect_reset_token_bypass', detail: user.email },
    })
    if (priorBypass) {
      await writeEvent(prisma, 'vuln_detect_reset_bypass_confirmed')
    }

    const token = issueSession(req.app, user)
    res.cookie('session', token, { httpOnly: true })
    res.status(200).json({ message: 'Logged in' })
  })
)

router.post(
  '/register',
  asyncHandler(async (req, res) => {
    const prisma = req.app.locals.prisma
    const { username, email, password } = req.body || {}
    if (
      typeof username !== 'string' ||
      !username ||
      typeof email !== 'string' ||
      !email ||
      typeof password !== 'string' ||
      !password
    ) {
      return res.status(400).json({ error: 'username, email, and password are required' })
    }

    const existing = await prisma.user.findFirst({ where: { OR: [{ email }, { username }] } })
    if (existing) {
      return res.status(409).json({ error: 'email or username already registered' })
    }

    await prisma.user.create({
      data: {
        username,
        email,
        password,
        role: 'member',
        department: 'Unassigned',
        title: 'New Hire',
        salary: 55000,
        resetToken: generateResetToken(),
      },
    })
    res.status(201).json({ message: 'Registered' })
  })
)

module.exports = { router }
