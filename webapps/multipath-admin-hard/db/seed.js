const crypto = require('crypto')

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz'

function randomLowercase(length) {
  let out = ''
  for (let i = 0; i < length; i++) {
    out += LOWERCASE[crypto.randomInt(LOWERCASE.length)]
  }
  return out
}

const FILLER_WORKSPACES = [
  {
    name: 'Brightline Logistics',
    members: [
      { email: 'priya.nair@brightline-logistics.example', role: 'admin' },
      { email: 'omar.diaz@brightline-logistics.example', role: 'member' },
      { email: 'kate.summers@brightline-logistics.example', role: 'member' },
    ],
    tickets: [
      { subject: 'Shipment tracking widget shows stale ETA', status: 'open' },
      { subject: 'Bulk CSV import fails for routes over 500 stops', status: 'open' },
      { subject: 'Add a dark mode toggle to the dispatch board', status: 'closed' },
      { subject: 'Driver app push notifications arrive twice', status: 'closed' },
    ],
  },
  {
    name: 'Cedar & Vine Cafés',
    members: [
      { email: 'jordan.lee@cedarandvine.example', role: 'admin' },
      { email: 'ana.ferreira@cedarandvine.example', role: 'member' },
    ],
    tickets: [
      { subject: 'Loyalty points not syncing across locations', status: 'open' },
      { subject: 'Receipt printer template misaligned on new POS', status: 'open' },
      { subject: 'Request: export monthly sales as PDF', status: 'closed' },
    ],
  },
  {
    name: 'Almora Health Partners',
    members: [
      { email: 'sam.okafor@almorahealth.example', role: 'admin' },
      { email: 'lena.wu@almorahealth.example', role: 'member' },
      { email: 'devon.brooks@almorahealth.example', role: 'member' },
    ],
    tickets: [
      { subject: 'Appointment reminders not sent for reschedules', status: 'open' },
      { subject: 'Patient portal login times out too quickly', status: 'closed' },
      { subject: 'Add insurance provider to intake form dropdown', status: 'open' },
      { subject: 'Duplicate patient records after merge', status: 'closed' },
      { subject: 'Referral letters missing clinician signature block', status: 'closed' },
    ],
  },
]

const FILLER_SAVED_VIEWS = [
  { ownerEmail: 'priya.nair@brightline-logistics.example', name: 'My open tickets', filterString: 'status:open' },
  { ownerEmail: 'jordan.lee@cedarandvine.example', name: 'Closed this quarter', filterString: 'status:closed' },
  { ownerEmail: 'sam.okafor@almorahealth.example', name: 'Everything open', filterString: 'status:open' },
]

const FILLER_PASSWORD = 'password123'
const PLATFORM_WORKSPACE_NAME = 'Thornfield Operations'
const PLATFORM_ADMIN_EMAIL = 'admin@thornfield.internal'

function insertWorkspace(db, name, isSeed) {
  const { lastInsertRowid } = db
    .prepare('INSERT INTO workspaces (name, is_seed) VALUES (?, ?)')
    .run(name, isSeed ? 1 : 0)
  return lastInsertRowid
}

function insertUser(db, workspaceId, email, password, role) {
  const { lastInsertRowid } = db
    .prepare('INSERT INTO users (workspace_id, email, password, role) VALUES (?, ?, ?, ?)')
    .run(workspaceId, email, password, role)
  return lastInsertRowid
}

function seedDb(db) {
  const userIdByEmail = {}

  for (const workspace of FILLER_WORKSPACES) {
    const workspaceId = insertWorkspace(db, workspace.name, true)
    for (const member of workspace.members) {
      userIdByEmail[member.email] = insertUser(db, workspaceId, member.email, FILLER_PASSWORD, member.role)
    }
    for (const ticket of workspace.tickets) {
      db.prepare('INSERT INTO tickets (workspace_id, subject, status) VALUES (?, ?, ?)').run(
        workspaceId,
        ticket.subject,
        ticket.status
      )
    }
  }

  for (const view of FILLER_SAVED_VIEWS) {
    db.prepare('INSERT INTO saved_views (user_id, name, filter_string) VALUES (?, ?, ?)').run(
      userIdByEmail[view.ownerEmail],
      view.name,
      view.filterString
    )
  }

  const platformWorkspaceId = insertWorkspace(db, PLATFORM_WORKSPACE_NAME, true)
  const adminPassword = randomLowercase(8)
  insertUser(db, platformWorkspaceId, PLATFORM_ADMIN_EMAIL, adminPassword, 'admin')

  return {
    platformAdminEmail: PLATFORM_ADMIN_EMAIL,
    platformAdminPassword: adminPassword,
  }
}

module.exports = {
  seedDb,
  randomLowercase,
  PLATFORM_ADMIN_EMAIL,
  PLATFORM_WORKSPACE_NAME,
  FILLER_WORKSPACES,
}
