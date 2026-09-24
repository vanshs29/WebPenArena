const { buildSchema } = require('graphql')
const { resolvers } = require('./resolvers')

const SDL = `
  type Query {
    me: Member
    organization(id: ID!): Organization
    team(id: ID!): Team
    organizationDirectory: [OrganizationSummary!]!
    publicIntegrations: [Integration!]!
    incidentResponseSquad(incidentId: ID!): [Member!]!
  }

  type OrganizationSummary {
    id: ID!
    name: String!
  }

  type Organization {
    id: ID!
    name: String!
    members: [Member!]!
  }

  type Member {
    id: ID!
    name: String!
    email: String!
    apiKeys: [ApiKey!]!
  }

  type ApiKey {
    id: ID!
    label: String!
    key: String!
  }

  type Team {
    id: ID!
    name: String!
    integrations: [Integration!]!
  }

  type Integration {
    id: ID!
    name: String!
    description: String!
    credentials: String!
  }
`

function buildMeridianSchema() {
  const schema = buildSchema(SDL)

  const queryFields = schema.getQueryType().getFields()
  for (const [fieldName, resolver] of Object.entries(resolvers.Query)) {
    queryFields[fieldName].resolve = resolver
  }

  const organizationFields = schema.getType('Organization').getFields()
  organizationFields.members.resolve = resolvers.Organization.members

  const teamFields = schema.getType('Team').getFields()
  teamFields.integrations.resolve = resolvers.Team.integrations

  const integrationFields = schema.getType('Integration').getFields()
  integrationFields.credentials.resolve = resolvers.Integration.credentials

  const memberFields = schema.getType('Member').getFields()
  memberFields.apiKeys.resolve = resolvers.Member.apiKeys

  return schema
}

module.exports = { SDL, buildMeridianSchema }
