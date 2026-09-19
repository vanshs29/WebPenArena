const express = require('express')
const { requireAuth } = require('../auth')
const { writeEvent } = require('../scoring')
const { asyncHandler } = require('../asyncHandler')

const router = express.Router()

const DOCUMENTED_FIELDS = new Set(['department', 'title'])

function coerceQueryValue(value) {
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      Object.entries(value).map(([op, v]) => [op, isNaN(v) ? v : Number(v)])
    )
  }
  return isNaN(value) ? value : Number(value)
}

function isExactSalaryFilter(salaryFilter) {
  if (typeof salaryFilter === 'number') return true
  if (typeof salaryFilter === 'object' && salaryFilter !== null) {
    const lower =
      'gte' in salaryFilter ? salaryFilter.gte : 'gt' in salaryFilter ? salaryFilter.gt + 1 : -Infinity
    const upper =
      'lte' in salaryFilter ? salaryFilter.lte : 'lt' in salaryFilter ? salaryFilter.lt - 1 : Infinity
    return Number.isFinite(lower) && Number.isFinite(upper) && upper - lower <= 0
  }
  return false
}

function toDirectoryEntries(users) {
  return users.map((u) => ({ name: u.username, department: u.department, title: u.title }))
}

router.get(
  '/directory',
  requireAuth,
  asyncHandler(async (req, res) => {
    const prisma = req.app.locals.prisma
    const results = await prisma.user.findMany({ orderBy: { id: 'asc' } })
    res.render('directory', { user: req.user, results: toDirectoryEntries(results) })
  })
)

router.get(
  '/directory/search',
  requireAuth,
  asyncHandler(async (req, res) => {
    const prisma = req.app.locals.prisma
    const where = {}
    let hasUndocumentedField = false
    for (const [key, value] of Object.entries(req.query)) {
      where[key] = coerceQueryValue(value)
      if (!DOCUMENTED_FIELDS.has(key)) hasUndocumentedField = true
    }

    const results = await prisma.user.findMany({ where })

    if (hasUndocumentedField) {
      await writeEvent(prisma, 'recon_search_no_allowlist')
    }

    if (
      'salary' in where &&
      isExactSalaryFilter(where.salary) &&
      results.some((u) => u.role === 'admin')
    ) {
      await writeEvent(prisma, 'exploit_admin_salary_extracted')
    }

    res.render('directory', { user: req.user, results: toDirectoryEntries(results) })
  })
)

module.exports = { router, coerceQueryValue, isExactSalaryFilter }
