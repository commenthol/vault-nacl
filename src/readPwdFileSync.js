const fs = require('fs')

const readFile = (filename) => fs.readFileSync(filename, 'utf8')
const readPwdFileSync = (filename) => {
  const pwd = readFile(filename)
    .replace(/^\s*[\n\r]/g, '')
    .split(/[\n\r]/g)[0].trim()
  if (!pwd) throw new Error('No password found in ' + filename)
  return pwd
}

module.exports = readPwdFileSync
