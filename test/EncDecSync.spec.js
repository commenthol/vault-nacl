const { strictEqual, deepStrictEqual, ...assert } = require('assert')
const { EncDecSync, Vault } = require('..')
const log = require('debug')('test:EncDecSync')

const ENC_VALUE = 'VAULT_NACL(###)'
const replacer = (str) => str.replace(/VAULT_NACL\([A-Za-z0-9/+=]+\)/g, ENC_VALUE)

describe('EncDecSync', function () {
  const password = 'pa$$w0rd'
  // encrypted values
  const values = () => ({
    val1: 'VAULT_NACL(AQAQJwAAVtajI7Ms2OChOs+ijD7yeuRQxbtfUnmSweH1kh1yQuBwtY2OSTLHMzlZFZfl7bM0C3A/FgzsSX3GPFMB)',
    other: [
      'unencrypted VAULT_NACL(AQAQJwAASskruqjibn3w5Rb+h76peEi4WhnXTHmw50MmFVJNmnlcM4FdNrzyjeRuArUM/p5I/AezdsSdrBcEFuLO+gNk)'
    ]
  })

  it('should encrypt object values', function () {
    const values = {
      val1: 'VAULT_NACL(encrypt this)VAULT_NACL',
      other: [
        'unencrypted VAULT_NACL(encrypt as well)VAULT_NACL'
      ]
    }
    const encdec = new EncDecSync(password)
    const result = encdec.encrypt(values)
    log(result)
    strictEqual(replacer(result.val1), ENC_VALUE)
    strictEqual(replacer(result.other[0]), `unencrypted ${ENC_VALUE}`)
  })

  it('should encrypt object values ignoring circularities', function () {
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
    const encdec = new EncDecSync(password)
    const result = encdec.encrypt(values)
    log(result)
    strictEqual(replacer(result.val1), ENC_VALUE)
    strictEqual(replacer(result.other[0]), `unencrypted ${ENC_VALUE}`)
  })

  it('should decrypt object values', function () {
    const exp = {
      val1: 'encrypt this',
      other: ['unencrypted encrypt as well']
    }
    const encdec = new EncDecSync(password)
    const result = encdec.decrypt(values())
    log(result)
    deepStrictEqual(result, exp)
  })

  it('should not decrypt object values on cleared vault', function () {
    const encdec = new EncDecSync(password)
    encdec.clear()
    assert.throws(() => {
      encdec.decrypt(values())
    }, /^Error: No password$/)
  })

  it('should encrypt string values', function () {
    const values = {
      val1: 'VAULT_NACL(encrypt this)VAULT_NACL',
      other: [
        'unencrypted VAULT_NACL(encrypt as well)VAULT_NACL'
      ]
    }
    const encdec = new EncDecSync(password)
    const result = encdec.encrypt(JSON.stringify(values))
    log(result)
    strictEqual(replacer(result), '{"val1":"VAULT_NACL(###)","other":["unencrypted VAULT_NACL(###)"]}')
  })

  it('should decrypt string values', function () {
    const encdec = new EncDecSync(password)
    const result = encdec.decrypt(JSON.stringify(values()))
    log(result)
    deepStrictEqual(result, '{"val1":"encrypt this","other":["unencrypted encrypt as well"]}')
  })

  it('should encrypt new object value ', function () {
    const _values = Object.assign({
      val2: 'VAULT_NACL(value2)VAULT_NACL'
    }, values())
    const encdec = new EncDecSync(password)
    const resultEnc = encdec.encrypt(_values)
    log(resultEnc)
    // all encrypted
    strictEqual(replacer(JSON.stringify(resultEnc)), '{"val2":"VAULT_NACL(###)","val1":"VAULT_NACL(###)","other":["unencrypted VAULT_NACL(###)"]}')

    const resultDec = encdec.decrypt(resultEnc)
    log(resultDec)
    deepStrictEqual(resultDec, {
      other: [
        'unencrypted encrypt as well'
      ],
      val1: 'encrypt this',
      val2: 'value2'
    })
  })

  it('should throw if encrypt new object value uses wrong password', function () {
    const _values = Object.assign({
      val2: 'VAULT_NACL(value2)VAULT_NACL'
    }, values())
    const encdec = new EncDecSync('wrong password')
    assert.throws(() => {
      encdec.encrypt(_values)
    }, /^Error: Decrypt failed/)
  })

  it('re-encrypt shall fail if vault is of wrong type', function () {
    const _values = Object.assign({
      val2: 'VAULT_NACL(value2)VAULT_NACL'
    }, values())
    const encdec = new EncDecSync(password)
    assert.throws(() => {
      encdec.rekey(_values, 1234)
    }, /^Error: Need instanceof Vault$/)
  })

  it('shall en-decrypt base64 values', function () {
    const encdec = new EncDecSync(password)
    const secret = Buffer.from('a thing is a thing is a thing is a thing').toString('base64').replace(/=/g, '')
    const encrypted = encdec.encrypt(`VAULT_NACL(${secret})VAULT_NACL`)
    console.log(encrypted)
    const decrypted = encdec.decrypt(encrypted)
    strictEqual(decrypted, secret)
  })

  describe('should re-encrypt new object value using different password', function () {
    const newPassword = 'new-password'
    let resultEnc
    let encdec

    it('shall re-encrypt with new password', function () {
      const _values = Object.assign({
        val2: 'VAULT_NACL(value2)VAULT_NACL'
      }, values())
      encdec = new EncDecSync(password)

      resultEnc = encdec.rekey(_values, newPassword)
      log(resultEnc)
      // all encrypted
      strictEqual(replacer(JSON.stringify(resultEnc)), '{"val2":"VAULT_NACL(###)","val1":"VAULT_NACL(###)","other":["unencrypted VAULT_NACL(###)"]}')
    })

    it('shall not decrypt with old password any longer', function () {
      assert.ok(resultEnc, 'need resultEnc from previous test')
      try {
        encdec.decrypt(resultEnc)
        assert.ok(false, 'shall not decrypt with old password any longer')
      } catch (e) {
        strictEqual(e.message, 'Decrypt failed at "val2"')
      }
    })

    it('shall decrypt with new password', function () {
      assert.ok(resultEnc, 'need resultEnc from previous test')
      const encdecNew = new EncDecSync(newPassword)
      const resultDec = encdecNew.decrypt(resultEnc)
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

  describe('should re-encrypt new object value using different vault', function () {
    const newPassword = 'new-password'
    let resultEnc
    let encdec

    it('shall re-encrypt with new password', function () {
      const _values = Object.assign({
        val2: 'VAULT_NACL(value2)VAULT_NACL'
      }, values())
      encdec = new EncDecSync(password)

      const newVault = new Vault(newPassword, { digest: 'sha512' })
      resultEnc = encdec.rekey(_values, newVault)
      log(resultEnc)
      // all encrypted
      strictEqual(replacer(JSON.stringify(resultEnc)), '{"val2":"VAULT_NACL(###)","val1":"VAULT_NACL(###)","other":["unencrypted VAULT_NACL(###)"]}')
    })

    it('shall not decrypt with old password any longer', function () {
      assert.ok(resultEnc, 'need resultEnc from previous test')
      try {
        encdec.decrypt(resultEnc)
        assert.ok(false, 'shall not decrypt with old password any longer')
      } catch (e) {
        strictEqual(e.message, 'Decrypt failed at "val2"')
      }
    })

    it('shall decrypt with new password', function () {
      assert.ok(resultEnc, 'need resultEnc from previous test')
      const encdecNew = new EncDecSync(newPassword)
      const resultDec = encdecNew.decrypt(resultEnc)
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
