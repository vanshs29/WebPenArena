const express = require('express')
const { requireAuth, requireAdmin } = require('../auth')
const { writeEvent } = require('../scoring')
const { asyncHandler } = require('../asyncHandler')

const router = express.Router()

router.get(
  '/admin/payroll',
  requireAuth,
  requireAdmin,
  asyncHandler(async (req, res) => {
    const prisma = req.app.locals.prisma
    await writeEvent(prisma, 'exploit_admin_action_confirmed')
    const employees = await prisma.user.findMany({ orderBy: { id: 'asc' } })
    res.render('adminPayroll', { user: req.user, employees })
  })
)

module.exports = { router }
