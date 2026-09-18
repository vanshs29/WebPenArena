const fs = require('fs')
const path = require('path')

function listJsFilesRecursively(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true })
  let files = []
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      files = files.concat(listJsFilesRecursively(fullPath))
    } else if (entry.name.endsWith('.js')) {
      files.push(fullPath)
    }
  }
  return files
}

// Naive, non-nested catch-block extraction: sufficient here because none of this app's
// catch blocks contain nested braces.
function findSwallowingCatches(source) {
  const matches = [...source.matchAll(/catch\s*(?:\([^)]*\))?\s*{([^}]*)}/g)]
  return matches.filter(([, body]) => !body.includes('res.') && !body.includes('throw'))
}

describe('only requireWorkspaceAdmin and requireTicketOwner swallow an exception and continue', () => {
  const appDir = path.join(__dirname, '..', 'app')

  test('authz.js contains exactly two swallowing catch blocks', () => {
    const source = fs.readFileSync(path.join(appDir, 'authz.js'), 'utf8')
    expect(findSwallowingCatches(source).length).toBe(2)
  })

  test('no other file under app/ contains a swallowing catch block', () => {
    for (const file of listJsFilesRecursively(appDir)) {
      if (file === path.join(appDir, 'authz.js')) continue
      const source = fs.readFileSync(file, 'utf8')
      expect(findSwallowingCatches(source)).toEqual([])
    }
  })
})

