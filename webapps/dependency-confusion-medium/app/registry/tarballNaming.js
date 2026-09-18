function shortName(pkgName) {
  const idx = pkgName.indexOf('/')
  return idx === -1 ? pkgName : pkgName.slice(idx + 1)
}

function filenameForVersion(pkgName, version) {
  return `${shortName(pkgName)}-${version}.tgz`
}

function versionFromFilename(pkgName, filename) {
  const prefix = `${shortName(pkgName)}-`
  const suffix = '.tgz'
  if (!filename.startsWith(prefix) || !filename.endsWith(suffix)) return null
  return filename.slice(prefix.length, filename.length - suffix.length)
}

module.exports = { shortName, filenameForVersion, versionFromFilename }
