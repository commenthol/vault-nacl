const fs = require('fs')
const { strictEqual, deepStrictEqual, ...assert } = require('assert')
const { EncDec, Vault } = require('../src')
const log = require('debug')('test:EncDec')

const ENC_VALUE = 'VAULT_NACL(###)'
const replacer = (str) => str.replace(/VAULT_NACL\([A-Za-z0-9/+=]+\)/g, ENC_VALUE)

describe('EncDec', function () {
  const password = 'pa$$w0rd'
  // encrypted values
  const values = () => ({
    val1: 'VAULT_NACL(AQAQJwAAVtajI7Ms2OChOs+ijD7yeuRQxbtfUnmSweH1kh1yQuBwtY2OSTLHMzlZFZfl7bM0C3A/FgzsSX3GPFMB)',
    other: [
      'unencrypted VAULT_NACL(AQAQJwAASskruqjibn3w5Rb+h76peEi4WhnXTHmw50MmFVJNmnlcM4FdNrzyjeRuArUM/p5I/AezdsSdrBcEFuLO+gNk)'
    ]
  })

  it('should encrypt object values', async function () {
    const values = {
      val1: 'VAULT_NACL(encrypt this)VAULT_NACL',
      other: [
        'unencrypted VAULT_NACL(encrypt as well)VAULT_NACL'
      ]
    }
    const encdec = new EncDec(password)
    const result = await encdec.encrypt(values)
    log(result)
    strictEqual(replacer(result.val1), ENC_VALUE)
    strictEqual(replacer(result.other[0]), `unencrypted ${ENC_VALUE}`)
  })

  it('should encrypt object values ignoring circularities', async function () {
    const values = {
      boolean: true,
      function: () => 'blabla',
      symbol: Symbol('symbol'),
      number: 1234,
      val1: 'VAULT_NACL(encrypt this)VAULT_NACL',
      other: [
        'unencrypted VAULT_NACL(encrypt as well)VAULT_NACL'
      ]
    }
    values.circular = values
    const encdec = new EncDec(password)
    const result = await encdec.encrypt(values)
    log(result)
    strictEqual(replacer(result.val1), ENC_VALUE)
    strictEqual(replacer(result.other[0]), `unencrypted ${ENC_VALUE}`)
  })

  it('should decrypt object values', async function () {
    const exp = {
      val1: 'encrypt this',
      other: ['unencrypted encrypt as well']
    }
    const encdec = new EncDec(password)
    const result = await encdec.decrypt(values())
    log(result)
    deepStrictEqual(result, exp)
  })

  it('should not decrypt object values on cleared vault', async function () {
    const encdec = new EncDec(password)
    encdec.clear()
    try {
      await encdec.decrypt(values())
      throw new Error()
    } catch (err) {
      assert.ok(/^No password$/.test(err.message))
    }
  })

  it('should encrypt string values', async function () {
    const values = {
      val1: 'VAULT_NACL(encrypt this)VAULT_NACL',
      other: [
        'unencrypted VAULT_NACL(encrypt as well)VAULT_NACL'
      ]
    }
    const encdec = new EncDec(password)
    const result = await encdec.encrypt(JSON.stringify(values))
    log(result)
    strictEqual(replacer(result), '{"val1":"VAULT_NACL(###)","other":["unencrypted VAULT_NACL(###)"]}')
  })

  it('should decrypt string values', async function () {
    const encdec = new EncDec(password)
    const result = await encdec.decrypt(JSON.stringify(values()))
    log(result)
    deepStrictEqual(result, '{"val1":"encrypt this","other":["unencrypted encrypt as well"]}')
  })

  it('should encrypt new object value ', async function () {
    const _values = Object.assign({
      val2: 'VAULT_NACL(value2)VAULT_NACL'
    }, values())
    const encdec = new EncDec(password)
    const resultEnc = await encdec.encrypt(_values)
    log(resultEnc)
    // all encrypted
    strictEqual(replacer(JSON.stringify(resultEnc)), '{"val2":"VAULT_NACL(###)","val1":"VAULT_NACL(###)","other":["unencrypted VAULT_NACL(###)"]}')

    const resultDec = await encdec.decrypt(resultEnc)
    log(resultDec)
    deepStrictEqual(resultDec, {
      other: [
        'unencrypted encrypt as well'
      ],
      val1: 'encrypt this',
      val2: 'value2'
    })
  })

  it('should throw if encrypt new object value uses wrong password', async function () {
    const _values = Object.assign({
      val2: 'VAULT_NACL(value2)VAULT_NACL'
    }, values())
    const encdec = new EncDec('wrong password')
    try {
      await encdec.encrypt(_values)
      throw new Error()
    } catch (err) {
      assert.ok(/^Decrypt failed$/.test(err.message))
    }
  })

  it('re-encrypt shall fail if vault is of wrong type', async function () {
    const _values = Object.assign({
      val2: 'VAULT_NACL(value2)VAULT_NACL'
    }, values())
    const encdec = new EncDec(password)
    try {
      await encdec.rekey(_values, 1234)
      throw new Error()
    } catch (err) {
      assert.ok(/^Need instanceof Vault$/.test(err.message))
    }
  })

  it('shall en-decrypt base64 values', async function () {
    const encdec = new EncDec(password)
    const secret = Buffer.from('a thing is a thing is a thing is a thing').toString('base64').replace(/=/g, '')
    const encrypted = await encdec.encrypt(`VAULT_NACL(${secret})VAULT_NACL`)
    const decrypted = await encdec.decrypt(encrypted)
    strictEqual(decrypted, secret)
  })

  it('shall check for vaults', async function () {
    const encdec = new EncDec(password)
    const hasVaults = await encdec.check(values())
    assert.ok(hasVaults)
  })

  it('shall split long lines', async function () {
    const lorem = fs.readFileSync(`${__dirname}/fixtures/lorem.txt`, 'utf8')
    const encdec = new EncDec(password)

    const encrypted = await encdec.encryptString(lorem)
    assert.ok(/^VAULT_NACL\(\n\w/.test(encrypted))

    const decrypted = await encdec.decrypt(encrypted)
    strictEqual(decrypted, lorem)
  })

  it('shall throw if encryptString is used with an object', async function () {
    try {
      const encdec = new EncDec(password)
      await encdec.encryptString({ test: 1 })
      throw new Error()
    } catch (err) {
      assert.ok(/^string expected$/.test(err.message))
    }
  })

  it('_replaceEncMode no args', async function () {
    const encdec = new EncDec(password)
    const out = await encdec._replaceEncMode()
    strictEqual(out, '')
  })

  it('shall encrypt new value', async function () {
    const values = [
      'VAULT_NACL(AQAQJwAAVtajI7Ms2OChOs+ijD7yeuRQxbtfUnmSweH1kh1yQuBwtY2OSTLHMzlZFZfl7bM0C3A/FgzsSX3GPFMB)',
      'VAULT_NACL(new value)VAULT_NACL',
      'test',
      'VAULT_NACL(AQAQJwAAVtajI7Ms2OChOs+ijD7yeuRQxbtfUnmSweH1kh1yQuBwtY2OSTLHMzlZFZfl7bM0C3A/FgzsSX3GPFMB)'
    ].join('\n')
    const encdec = new EncDec(password)
    const out = await encdec.encrypt(values)
    log(out)
    const res = out.match(/VAULT_NACL/g)
    strictEqual(res.length, 3)
  })

  describe('should re-encrypt new object value using different password', async function () {
    const newPassword = 'new-password'
    let resultEnc
    let encdec

    it('shall re-encrypt with new password', async function () {
      const _values = Object.assign({
        val2: 'VAULT_NACL(value2)VAULT_NACL'
      }, values())
      const val1 = _values.val1
      const other = _values.other[0]

      encdec = new EncDec(password)
      log(_values)
      resultEnc = await encdec.rekey(_values, newPassword)
      log(resultEnc)
      // all encrypted
      assert.ok(val1 !== resultEnc.val1, 'val1 shall be different')
      assert.ok(other !== resultEnc.other[0], 'other[0] shall be different')
      strictEqual(replacer(JSON.stringify(resultEnc)),
        '{"val2":"VAULT_NACL(###)","val1":"VAULT_NACL(###)","other":["unencrypted VAULT_NACL(###)"]}')
    })

    it('shall re-encrypt file with new password', async function () {
      const lorem = fs.readFileSync(`${__dirname}/fixtures/lorem.txt`, 'utf8')
      const encdec = new EncDec(password)

      const encrypted = await encdec.encryptString(lorem)
      log('encrypted', encrypted)
      const rekeyed = await encdec.rekey(encrypted, newPassword)
      log('rekeyed', rekeyed)
      assert.ok(/\s/.test(rekeyed))
      const encdec2 = new EncDec(newPassword)
      const decrypted = await encdec2.decrypt(rekeyed)
      log('decrypted', decrypted)
      strictEqual(decrypted, lorem)
    })

    it('shall not decrypt with old password any longer', async function () {
      assert.ok(resultEnc, 'need resultEnc from previous test')
      try {
        await encdec.decrypt(resultEnc)
        assert.ok(false, 'shall not decrypt with old password any longer')
      } catch (e) {
        strictEqual(e.message, 'Decrypt failed')
      }
    })

    it('shall decrypt with new password', async function () {
      assert.ok(resultEnc, 'need resultEnc from previous test')
      const encdecNew = new EncDec(newPassword)
      const resultDec = await encdecNew.decrypt(resultEnc)
      log(resultDec)
      deepStrictEqual(resultDec, {
        other: [
          'unencrypted encrypt as well'
        ],
        val1: 'encrypt this',
        val2: 'value2'
      })
    })
  })

  describe('should re-encrypt new object value using different vault', async function () {
    const newPassword = 'new-password'
    let resultEnc
    let encdec

    it('shall re-encrypt with new password', async function () {
      const _values = Object.assign({
        val2: 'VAULT_NACL(value2)VAULT_NACL'
      }, values())
      encdec = new EncDec(password)

      const newVault = new Vault(newPassword, { digest: 'sha512' })
      resultEnc = await encdec.rekey(_values, newVault)
      log(resultEnc)
      // all encrypted
      strictEqual(replacer(JSON.stringify(resultEnc)), '{"val2":"VAULT_NACL(###)","val1":"VAULT_NACL(###)","other":["unencrypted VAULT_NACL(###)"]}')
    })

    it('shall not decrypt with old password any longer', async function () {
      assert.ok(resultEnc, 'need resultEnc from previous test')
      try {
        await encdec.decrypt(resultEnc)
        assert.ok(false, 'shall not decrypt with old password any longer')
      } catch (e) {
        strictEqual(e.message, 'Decrypt failed')
      }
    })

    it('shall decrypt with new password', async function () {
      assert.ok(resultEnc, 'need resultEnc from previous test')
      const encdecNew = new EncDec(newPassword)
      const resultDec = await encdecNew.decrypt(resultEnc)
      log(resultDec)
      deepStrictEqual(resultDec, {
        other: [
          'unencrypted encrypt as well'
        ],
        val1: 'encrypt this',
        val2: 'value2'
      })
    })
  })
})
