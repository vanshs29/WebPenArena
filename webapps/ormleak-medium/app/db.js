const crypto = require('crypto')
const { generateResetToken } = require('./auth')
const { ADMIN_EMAIL, ADMIN_SALARY } = require('./constants')

function generatePassword() {
  return crypto.randomBytes(9).toString('base64').replace(/[^a-zA-Z0-9]/g, '')
}

const FILLER_EMPLOYEES = [
  {
    username: 'maria',
    email: 'maria@fernhollow.local',
    department: 'Marketing',
    title: 'Marketing Coordinator',
    salary: 62000,
  },
  {
    username: 'devon',
    email: 'devon@fernhollow.local',
    department: 'Engineering',
    title: 'Software Engineer',
    salary: 98000,
  },
  {
    username: 'priya',
    email: 'priya@fernhollow.local',
    department: 'Finance',
    title: 'Financial Analyst',
    salary: 71000,
  },
]

async function seedDb(prisma) {
  const adminPassword = generatePassword()
  await prisma.user.create({
    data: {
      username: 'admin',
      email: ADMIN_EMAIL,
      password: adminPassword,
      role: 'admin',
      department: 'Executive',
      title: 'Chief Executive Officer',
      salary: ADMIN_SALARY,
      resetToken: generateResetToken(),
    },
  })

  for (const emp of FILLER_EMPLOYEES) {
    await prisma.user.create({
      data: {
        ...emp,
        password: generatePassword(),
        role: 'member',
        resetToken: generateResetToken(),
      },
    })
  }

  return { adminPassword }
}

async function resetDb(prisma) {
  await prisma.scoringEvent.deleteMany()
  await prisma.user.deleteMany()
  await seedDb(prisma)
}

module.exports = { seedDb, resetDb, FILLER_EMPLOYEES }
