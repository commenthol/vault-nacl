const fs = require('fs')
const assert = require('assert')
const { execSync } = require('child_process')
const log = require('debug')('test:cli')

const fixtures = `${__dirname}/fixtures`
const bin = `${__dirname}/../bin/vault-nacl.js`

describe('cli', function () {
  it('shall decrypt file', function () {
    const filename = `${fixtures}/example.txt`
    const res = execSync([bin, 'decrypt', '-p', 'secret', filename].join(' '))
    log(JSON.stringify(res.toString()))
    assert.strictEqual(res.toString(), "open with \"secret\"\nSesame opened...\n\ntest: 'encrypt this\n\nover some\n\nlines'\n\n")
  })

  it('shall encrypt file', function () {
    const filename = `${fixtures}/encrypt.txt`
    const res = execSync([bin, 'encrypt', '-p', 'secret', '-o', filename + '.vault', filename].join(' '))
    assert.strictEqual(res.toString(), '')
  })

  it('shall re-encrypt file', function () {
    const filename = `${fixtures}/encrypt.txt`
    const res = execSync([
      bin,
      'rekey',
      '--password',
      'secret',
      '--new-password',
      'newSecret',
      '--output',
      filename + '.1.vault',
      filename + '.vault'].join(' '))
    assert.strictEqual(res.toString(), '')
  })

  it('shall decrypt re-encrypted file', function () {
    const filename = `${fixtures}/encrypt.txt`
    const res = execSync([
      bin,
      'decrypt',
      '--password',
      'newSecret',
      filename + '.1.vault'].join(' '))
    log(JSON.stringify(res.toString()))
    assert.strictEqual(res.toString(), "test: 'encrypt this\n\nover some\n\nlines'\n\nleave unencrypted\n\n")
  })

  it('shall encrypt complete text file', function () {
    const filename = `${fixtures}/lorem.txt`
    const res = execSync([
      bin,
      'encrypt',
      '--password',
      'secret',
      '-o',
      filename + '.vault',
      filename].join(' '))
    log(JSON.stringify(res.toString()))
    assert.strictEqual(res.toString(), '')
  })

  it('shall decrypt complete text file', function () {
    const filename = `${fixtures}/lorem.txt`
    const res = execSync([
      bin,
      'decrypt',
      '--password',
      'secret',
      '-o',
      filename + '.0.vault',
      filename].join(' '))
    log(JSON.stringify(res.toString()))
    assert.strictEqual(res.toString(), '')
    const file1 = fs.readFileSync(filename, 'utf8')
    const file2 = fs.readFileSync(filename + '.0.vault', 'utf8')
    assert.strictEqual(file1, file2)
  })
})
