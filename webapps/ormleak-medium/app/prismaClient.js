const { PrismaClient } = require('@prisma/client')

function createPrismaClient(databaseUrl) {
  const options = { errorFormat: 'minimal' }
  if (databaseUrl) options.datasourceUrl = databaseUrl
  return new PrismaClient(options)
}

module.exports = { createPrismaClient }
