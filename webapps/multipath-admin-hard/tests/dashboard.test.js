const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('score dashboard', () => {
  test('renders all 11 exploration checkpoints and 12 non-exploration checkpoints', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.status).toBe(200)

    const explorationKeys = [
      'GET /', 'GET /login', 'POST /login', 'GET /register', 'POST /register',
      'GET /dashboard', 'GET /tickets', 'GET /saved-views', 'POST /saved-views',
      'GET /settings/general', 'GET /settings/import',
    ]
    const nonExplorationKeys = [
      'recon_saved_view_execution_decoupled', 'recon_import_deserializes_input',
      'recon_directory_sync_page_ungated', 'recon_sync_secret_disclosed',
      'vuln_detect_boolean_oracle_confirmed', 'vuln_detect_rce_confirmed',
      'vuln_detect_webhook_accepts_secret',
      'exploit_admin_password_extracted_and_logged_in',
      'exploit_workspace_settings_accessed_via_admin_login',
      'exploit_override_token_exfiltrated', 'exploit_override_login_succeeded',
      'exploit_self_role_elevated_via_webhook',
    ]

    for (const key of [...explorationKeys, ...nonExplorationKeys]) {
      expect(res.text).toContain(key)
    }
  })

  test('shows a Reset button and a link to the JSON API', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.text).toContain('Reset App')
    expect(res.text).toContain('?format=json')
  })

  test('shows a collapsible event log', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.text).toContain('Event Log')
  })
})
