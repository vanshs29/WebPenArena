const { GraphQLError } = require('graphql')
const { writeEvent, hasFired } = require('../app/scoring')

async function getOrganizationById(pool, id) {
  const { rows } = await pool.query('SELECT id, name FROM organizations WHERE id = $1', [id])
  return rows[0] || null
}

async function getMembersByOrgId(pool, orgId) {
  const { rows } = await pool.query(
    'SELECT id, name, email, org_id AS "orgId" FROM members WHERE org_id = $1 ORDER BY name',
    [orgId]
  )
  return rows
}

async function getTeamById(pool, id) {
  const { rows } = await pool.query(
    'SELECT id, name, org_id AS "orgId" FROM teams WHERE id = $1',
    [id]
  )
  return rows[0] || null
}

async function getIntegrationsByTeamId(pool, teamId) {
  const { rows } = await pool.query(
    `SELECT integrations.id, integrations.name, integrations.description,
            integrations.team_id AS "teamId", teams.org_id AS "orgId"
     FROM integrations JOIN teams ON teams.id = integrations.team_id
     WHERE integrations.team_id = $1
     ORDER BY integrations.name`,
    [teamId]
  )
  return rows
}

async function listOrganizationSummaries(pool) {
  const { rows } = await pool.query('SELECT id, name FROM organizations ORDER BY name')
  return rows
}

async function listMarketplaceIntegrations(pool) {
  const { rows } = await pool.query(
    `SELECT integrations.id, integrations.name, integrations.description,
            integrations.team_id AS "teamId", teams.org_id AS "orgId"
     FROM integrations JOIN teams ON teams.id = integrations.team_id
     WHERE integrations.is_marketplace_listed = TRUE
     ORDER BY integrations.name`
  )
  return rows
}

async function getIncidentById(pool, id) {
  const { rows } = await pool.query(
    'SELECT id, title, is_platform_wide AS "isPlatformWide" FROM incidents WHERE id = $1',
    [id]
  )
  return rows[0] || null
}

async function getResponseSquadMembers(pool, incidentId) {
  const { rows } = await pool.query(
    `SELECT members.id, members.name, members.email, members.org_id AS "orgId"
     FROM members
     JOIN incident_participants ip ON ip.org_id = members.org_id
     WHERE ip.incident_id = $1
     ORDER BY members.name`,
    [incidentId]
  )
  return rows
}

async function getIntegrationCredentialsById(pool, integrationId) {
  const { rows } = await pool.query('SELECT credentials FROM integrations WHERE id = $1', [
    integrationId,
  ])
  return rows[0] ? rows[0].credentials : null
}

async function getApiKeysByMemberId(pool, memberId) {
  const { rows } = await pool.query(
    'SELECT id, label, key FROM api_keys WHERE member_id = $1 ORDER BY label',
    [memberId]
  )
  return rows
}

async function maybeFireDirectCrossOrgBlocked(pool, which) {
  await writeEvent(pool, `_internal_${which}_blocked`)
  const orgBlocked = await hasFired(pool, '_internal_organization_blocked')
  const teamBlocked = await hasFired(pool, '_internal_team_blocked')
  if (orgBlocked && teamBlocked) {
    await writeEvent(pool, 'vuln_detect_direct_cross_org_blocked')
  }
}

async function maybeFireOwnFieldsRecon(pool, which) {
  await writeEvent(pool, `_internal_own_${which}_confirmed`)
  const credsConfirmed = await hasFired(pool, '_internal_own_credentials_confirmed')
  const apiKeysConfirmed = await hasFired(pool, '_internal_own_apiKeys_confirmed')
  if (credsConfirmed && apiKeysConfirmed) {
    await writeEvent(pool, 'recon_sensitive_fields_confirmed_own_org')
  }
}

const resolvers = {
  Query: {
    me: async (_parent, _args, ctx) => ctx.member,

    organization: async (_parent, args, ctx) => {
      if (String(ctx.member.orgId) !== String(args.id)) {
        await maybeFireDirectCrossOrgBlocked(ctx.pool, 'organization')
        throw new GraphQLError('not authorized')
      }
      return getOrganizationById(ctx.pool, args.id)
    },

    team: async (_parent, args, ctx) => {
      const team = await getTeamById(ctx.pool, args.id)
      if (!team || String(team.orgId) !== String(ctx.member.orgId)) {
        await maybeFireDirectCrossOrgBlocked(ctx.pool, 'team')
        throw new GraphQLError('not authorized')
      }
      return team
    },

    organizationDirectory: async (_parent, _args, ctx) => listOrganizationSummaries(ctx.pool),

    publicIntegrations: async (_parent, _args, ctx) => listMarketplaceIntegrations(ctx.pool),

    incidentResponseSquad: async (_parent, args, ctx) => {
      const incident = await getIncidentById(ctx.pool, args.incidentId)
      if (!incident || !incident.isPlatformWide) {
        throw new GraphQLError('not found')
      }
      return getResponseSquadMembers(ctx.pool, args.incidentId)
    },
  },

  Organization: {
    members: async (parent, _args, ctx) => getMembersByOrgId(ctx.pool, parent.id),
  },

  Team: {
    integrations: async (parent, _args, ctx) => getIntegrationsByTeamId(ctx.pool, parent.id),
  },

  Integration: {
    credentials: async (parent, _args, ctx) => {
      const credentials = await getIntegrationCredentialsById(ctx.pool, parent.id)
      const isOwnOrg = String(parent.orgId) === String(ctx.member.orgId)
      if (isOwnOrg) {
        await maybeFireOwnFieldsRecon(ctx.pool, 'credentials')
      } else {
        await writeEvent(ctx.pool, 'vuln_detect_marketplace_pivot_confirmed')
      }
      return credentials
    },
  },

  Member: {
    apiKeys: async (parent, _args, ctx) => {
      const apiKeys = await getApiKeysByMemberId(ctx.pool, parent.id)
      const isOwnOrg = String(parent.orgId) === String(ctx.member.orgId)
      if (isOwnOrg) {
        await maybeFireOwnFieldsRecon(ctx.pool, 'apiKeys')
      } else {
        await writeEvent(ctx.pool, 'vuln_detect_squad_pivot_confirmed')
      }
      return apiKeys
    },
  },
}

module.exports = { resolvers }
