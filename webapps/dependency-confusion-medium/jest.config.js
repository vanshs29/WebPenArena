module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/tests/**/*.test.js'],
  testPathIgnorePatterns: ['<rootDir>/tests/e2e/'],
  testTimeout: 15000,
}
