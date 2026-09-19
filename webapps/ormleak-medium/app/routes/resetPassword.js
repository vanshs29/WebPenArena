const express = require('express')
const { generateResetToken } = require('../auth')
const { writeEvent } = require('../scoring')
const { asyncHandler } = require('../asyncHandler')

const router = express.Router()

router.get('/reset-password', (req, res) => res.render('resetPassword'))

router.get('/reset-password/confirm', (req, res) => res.render('resetConfirm'))

router.post(
  '/reset-password',
  asyncHandler(async (req, res) => {
    const prisma = req.app.locals.prisma
    const { email } = req.body || {}
    if (typeof email !== 'string' || !email) {
      return res.status(400).json({ error: 'email required' })
    }

    const user = await prisma.user.findUnique({ where: { email } })
    if (user) {
      await prisma.user.update({
        where: { id: user.id },
        data: { resetToken: generateResetToken() },
      })
    }

    res.status(200).json({
      message: 'If that email is registered, a reset code has been generated.',
    })
  })
)

router.post(
  '/reset-password/confirm',
  asyncHandler(async (req, res) => {
    const prisma = req.app.locals.prisma
    const { email, resetToken, newPassword } = req.body || {}
    if (typeof email !== 'string' || !email || typeof newPassword !== 'string' || !newPassword) {
      return res.status(400).json({ error: 'email, resetToken, and newPassword required' })
    }
    if (!('resetToken' in (req.body || {}))) {
      return res.status(400).json({ error: 'email, resetToken, and newPassword required' })
    }

    const user = await prisma.user.findFirst({ where: { email, resetToken } })
    if (!user) return res.status(401).json({ error: 'invalid email or token' })

    await prisma.user.update({
      where: { id: user.id },
      data: { password: newPassword, resetToken: generateResetToken() },
    })

    if (typeof resetToken === 'object' && resetToken !== null) {
      await writeEvent(prisma, 'vuln_detect_reset_token_bypass', email)
    }

    res.status(200).json({ status: 'password updated' })
  })
)

module.exports = { router }
