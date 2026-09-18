jest.mock('child_process')
const { execFile } = require('child_process')

describe('ciSimulator', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    jest.useFakeTimers()
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  test('runDependencySync invokes npm install with --prefix and --registry, inheriting env', () => {
    const { runDependencySync, PACKAGE_NAME } = require('../app/ciSimulator')
    process.env.SOME_MARKER = 'marker-value'

    runDependencySync({ registryUrl: 'http://127.0.0.1:5000/registry', ciWorkspace: '/tmp/ci-workspace' })

    expect(execFile).toHaveBeenCalledTimes(1)
    const [cmd, args, options] = execFile.mock.calls[0]
    expect(cmd).toBe('npm')
    expect(args).toEqual([
      'install',
      '--no-save',
      '--prefix',
      '/tmp/ci-workspace',
      '--registry',
      'http://127.0.0.1:5000/registry',
      PACKAGE_NAME,
    ])
    expect(options.env).toBe(process.env)
    expect(options.env.SOME_MARKER).toBe('marker-value')

    delete process.env.SOME_MARKER
  })

  test('runDependencySync falls back to REGISTRY_URL env var when no explicit registryUrl is given', () => {
    const { runDependencySync } = require('../app/ciSimulator')
    process.env.REGISTRY_URL = 'http://127.0.0.1:9999/registry'

    runDependencySync({ ciWorkspace: '/tmp/ci-workspace' })

    const [, args] = execFile.mock.calls[0]
    expect(args).toContain('http://127.0.0.1:9999/registry')

    delete process.env.REGISTRY_URL
  })

  test('startCiSimulator runs an immediate sync and schedules further ones on the interval', () => {
    const { startCiSimulator } = require('../app/ciSimulator')

    const handle = startCiSimulator({
      registryUrl: 'http://127.0.0.1:5000/registry',
      ciWorkspace: '/tmp/ci-workspace',
      syncIntervalMs: 15000,
    })

    expect(execFile).toHaveBeenCalledTimes(1)

    jest.advanceTimersByTime(15000)
    expect(execFile).toHaveBeenCalledTimes(2)

    jest.advanceTimersByTime(15000)
    expect(execFile).toHaveBeenCalledTimes(3)

    clearInterval(handle)
  })
})
