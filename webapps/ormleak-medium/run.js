const { createApp } = require('./app')
const { createPrismaClient } = require('./app/prismaClient')
const { seedDb } = require('./app/db')

async function main() {
  const prisma = createPrismaClient(process.env.DATABASE_URL)
  const existingCount = await prisma.user.count()
  if (existingCount === 0) {
    await seedDb(prisma)
  }

  const app = createApp({ prisma })
  const PORT = process.env.PORT || 5000

  app.listen(PORT, () => {
    console.log(`Fernhollow listening on http://localhost:${PORT}`)
  })
}

main()
