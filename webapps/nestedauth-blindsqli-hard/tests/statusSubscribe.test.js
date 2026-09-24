const request = require('supertest')
const { newTestApp } = require('./helpers')
const { TRUE_CONDITION_SLEEP_SECONDS, SLOW_THRESHOLD_SECONDS, FAST_THRESHOLD_SECONDS } = require('../app/routes/status')

describe('POST /status/subscribe', () => {
  test('a well-formed email always returns 200 subscribed', async () => {
    const app = await newTestApp()
    const res = await request(app)
      .post('/status/subscribe')
      .send({ email: 'plausible-nonexistent@example.com' })
    expect(res.status).toBe(200)
    expect(res.body.status).toBe('subscribed')
  })

  test('a real, already-subscribed email also returns 200 subscribed', async () => {
    const app = await newTestApp()
    await request(app).post('/status/subscribe').send({ email: 'repeat@example.com' })
    const res = await request(app).post('/status/subscribe').send({ email: 'repeat@example.com' })
    expect(res.status).toBe(200)
    expect(res.body.status).toBe('subscribed')
  })

  test('an unbalanced-quote email returns a generic 500 with no driver-specific detail', async () => {
    const app = await newTestApp()
    const res = await request(app)
      .post('/status/subscribe')
      .send({ email: "weird'quote@test.local" })
    expect(res.status).toBe(500)
    expect(JSON.stringify(res.body).toLowerCase()).not.toMatch(/postgres|syntax error|pg_|relation/)
  })

  test('missing email returns 400', async () => {
    const app = await newTestApp()
    const res = await request(app).post('/status/subscribe').send({})
    expect(res.status).toBe(400)
  })

  test(
    'a true-condition pg_sleep payload measurably delays the response versus a false-condition control',
    async () => {
      const app = await newTestApp()

      const falseStart = Date.now()
      await request(app)
        .post('/status/subscribe')
        .send({ email: "nodelay' AND 1=(SELECT 1 FROM pg_sleep(0))-- -@x.test" })
      const falseElapsed = (Date.now() - falseStart) / 1000

      const trueStart = Date.now()
      await request(app)
        .post('/status/subscribe')
        .send({
          email: `delay' AND 1=(SELECT 1 FROM pg_sleep(${TRUE_CONDITION_SLEEP_SECONDS}))-- -@x.test`,
        })
      const trueElapsed = (Date.now() - trueStart) / 1000

      expect(falseElapsed).toBeLessThan(FAST_THRESHOLD_SECONDS)
      expect(trueElapsed).toBeGreaterThan(SLOW_THRESHOLD_SECONDS)
    },
    (TRUE_CONDITION_SLEEP_SECONDS + 5) * 1000
  )
})
