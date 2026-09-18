const request = require('supertest')
const { newTestApp } = require('./helpers')

describe('public pages render', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  it('renders the homepage', async () => {
    const res = await request(app).get('/')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Northwire')
  })

  it('renders the articles index', async () => {
    const res = await request(app).get('/articles')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Northwire')
  })

  it('renders an article detail page', async () => {
    const res = await request(app).get('/articles/1')
    expect(res.status).toBe(200)
  })

  it('returns 404 for a nonexistent article', async () => {
    const res = await request(app).get('/articles/9999')
    expect(res.status).toBe(404)
  })

  it('renders the login page', async () => {
    const res = await request(app).get('/login')
    expect(res.status).toBe(200)
  })

  it('renders the register page', async () => {
    const res = await request(app).get('/register')
    expect(res.status).toBe(200)
  })

  it('seeds exactly three articles', async () => {
    const res = await request(app).get('/articles')
    expect(res.status).toBe(200)
    const matches = res.text.match(/article-item/g) || []
    expect(matches.length).toBe(3)
  })
})
