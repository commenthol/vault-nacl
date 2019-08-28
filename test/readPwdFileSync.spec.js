const assert = require('assert')
const { readPwdFileSync } = require('..')

describe('readPwdFileSync', function () {
  it('shall read password from file', function () {
    const filename = `${__dirname}/fixtures/pwdfile.txt`
    const pwd = readPwdFileSync(filename)
    assert.strictEqual(pwd, 'first line')
  })
  it('shall read password from file with multiple lines', function () {
    const filename = `${__dirname}/fixtures/pwdfileMulti.txt`
    const pwd = readPwdFileSync(filename)
    assert.strictEqual(pwd, 'first line')
  })
  it('shall fail on empty password file', function () {
    const filename = `${__dirname}/fixtures/empty.txt`
    assert.throws(() => {
      readPwdFileSync(filename)
    }, /No password found in/)
  })
})
