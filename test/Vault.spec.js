const { ok, strictEqual, ...assert } = require('assert')
const { Vault } = require('..')
const log = require('debug')('test:vault')

const nodeVersion = process.version.match(/(\d+)/g).map(n => parseInt(n))

const itcond = cond => cond ? it.skip : it

describe('vault', function () {
  const vaultSha256 = 'AQAQJwAAhDU2gJ4yAz/PKXJLDyVT2kohFeI0sKZaWPWaeTUUIDZJmn8ScyayjzDcp4qf6D8GFNhaND1zCa65pdG8Om4o'
  const vaultSha384 = 'AQEQJwAAY6h4r75uWoxc8MFbdmQNJhunb2XxjJw3fPDlV5qWCiGxA0t+nR+sxzufK5+xX5miiTVUM/ehvz6lUqmHM++r'
  const vaultSha512 = 'AQIQJwAArU1uPAoZ90Y698K8Z75/77UJwnI6NRep4UIW3jhJZI9Q2bgWFIFY5PcMwcdGZDbkBjxw3frfqJG139r2Lial'
  const vaultRipemd = 'AQMQJwAAesJtqQlZXtSXNyQ0/Y2P3+6KeLa7koyEEJestr6AmdQ6gqnbirTPUq+ej6ax7jbxw0VrGLNPrss7D8AzLZvt'
  const vaultWhirl = 'AQQQJwAAt/owWkB8fz2OxvKBMhfy1apP8yaVTOctgq4VZH2s4QAs2AUIdxpBCqD3PXLtiRM8Rm+f5jQ9f5LFcQkuE0Dp'
  const vaultBadDigest = 'Af8QJwAAFpDGDI96UgQHOSw9Wb0h69BmyOblevBmIXQOl3BQnN7s1JgHiLUGe548zpx41mVnHz7MWvoeCfq3+zAo6rQA'
  const vaultBadIterations = 'AQLoAwAAqb0oNUKcRIc79XcCpAeXaL1cVXNlY9pazb2/vg1dYdQlDxSogMnnH1Z3CpeC0gLYiKAc6c+z+t7Xg8t3ypgU'
  const vaultBadSalt = 'AQMQJwAAfEKv/3LDYwiAksBwInuc5cT38v8i43nJx88U/7A1/5tCJUj1JQLSNMh/8WxZgy8QiffS0EiMkHZo8+dG2QmU'
  const vaultBadBox = 'AQAQJwAAOmjNYKhkOUmZU9LBXZD+QV+S51Rn/jjESw2UqlebUAg/RYD/PSFVJjdoI4goT6uwlf3DxG33KINq/Ugy/mIw'
  const vaultBadVersion = '/wAQJwAAIu5r+YjzB39k2HnFSCaQBeZJWmyI+Hq+1/4ziAyUSw3rftGRCKD0lbLcucywQr3AFrP10O/bh7P54b3dZuYn'

  const secret = 'superSecret123!'
  const password = 'pa$$w0rd'

  it('shall not expose password', function () {
    const v = new Vault(password)
    const PASSWORD = Symbol('PASSWORD')
    strictEqual(v[PASSWORD], undefined)
  })

  it('shall fail if password is missing', function () {
    const v = new Vault()
    return v.decrypt(vaultSha256)
      .then(() => {
        ok(false, 'shall not reach here')
      })
      .catch(err => {
        strictEqual(err.message, 'No password')
      })
  })

  it('shall fail if password was cleared', function () {
    const v = new Vault(password)
    v.clear()

    return v.decrypt(vaultSha256)
      .then(() => {
        ok(false, 'shall not reach here')
      })
      .catch(err => {
        strictEqual(err.message, 'No password')
      })
  })

  it('shall fail on unknown digest', function () {
    const v = new Vault(password, { digest: 'unknown' })
    return v.encrypt(secret)
      .then(() => {
        ok(false, 'shall not reach here')
      })
      .catch(err => {
        strictEqual(err.message, 'Unsupported digest')
      })
  })

  it('shall fail on unknown digest (sync mode)', function () {
    const v = new Vault(password, { digest: 'unknown' })
    assert.throws(() => {
      v.encryptSync(secret)
    }, /Unsupported digest/)
  })

  it('shall decrypt with sha256 digest', function () {
    const v = new Vault(password)
    return v.decrypt(vaultSha256)
      .then(_secret => {
        strictEqual(_secret, secret)
      })
  })

  it('shall decrypt with sha256 digest synch', function () {
    const v = new Vault(password)
    const _secret = v.decryptSync(vaultSha256)
    strictEqual(_secret, secret)
  })

  it('shall decrypt with sha384 digest', function () {
    const v = new Vault(password)
    return v.decrypt(vaultSha384)
      .then(_secret => {
        strictEqual(_secret, secret)
      })
  })

  it('shall decrypt with sha512 digest', function () {
    const v = new Vault(password)
    return v.decrypt(vaultSha512)
      .then(_secret => {
        strictEqual(_secret, secret)
      })
  })

  // openssl in node@17 has dropped support for ripemd
  itcond(nodeVersion[0] > 16)('shall decrypt with ripemd digest', function () {
    const v = new Vault(password)
    return v.decrypt(vaultRipemd)
      .then(_secret => {
        strictEqual(_secret, secret)
      })
  })

  // openssl in node@17 has dropped support for whirlpool
  itcond(nodeVersion[0] > 16)('shall decrypt with whirlpool digest', function () {
    const v = new Vault(password)
    return v.decrypt(vaultWhirl)
      .then(_secret => {
        strictEqual(_secret, secret)
      })
  })

  it('shall encrypt and decrypt', function () {
    const v = new Vault(password)
    return v.encrypt(secret)
      .then(_vault => {
        log(_vault)
        return v.decrypt(_vault)
      })
      .then(_secret => {
        strictEqual(_secret, secret)
      })
  })

  ;['sha256', 'sha384', 'sha512'].forEach(digest => {
    it('shall encrypt and decrypt with ' + digest, function () {
      const v = new Vault(password, { digest })
      return v.encrypt(secret)
        .then(_vault => {
          log(_vault)
          return v.decrypt(_vault)
        })
        .then(_secret => {
          strictEqual(_secret, secret)
        })
    })
  })

  ;['ripemd', 'whirlpool'].forEach(digest => {
    itcond(nodeVersion[0] > 16)('shall encrypt and decrypt with ' + digest, function () {
      const v = new Vault(password, { digest })
      return v.encrypt(secret)
        .then(_vault => {
          log(_vault)
          return v.decrypt(_vault)
        })
        .then(_secret => {
          strictEqual(_secret, secret)
        })
    })
  })

  ;['sha256', 'sha384', 'sha512'].forEach(digest => {
    it('shall encrypt and decrypt with ' + digest + ' sync', function () {
      const v = new Vault(password, { digest })
      const _vault = v.encryptSync(secret)
      const _secret = v.decryptSync(_vault)
      strictEqual(_secret, secret)
    })
  })

  ;['ripemd', 'whirlpool'].forEach(digest => {
    itcond(nodeVersion[0] > 16)('shall encrypt and decrypt with ' + digest + ' sync', function () {
      const v = new Vault(password, { digest })
      const _vault = v.encryptSync(secret)
      const _secret = v.decryptSync(_vault)
      strictEqual(_secret, secret)
    })
  })

  it('shall fail on bad version', function () {
    const v = new Vault(password)
    return v.decrypt(vaultBadVersion)
      .then(() => {
        ok(false, 'shall not reach here')
      })
      .catch(err => {
        strictEqual(err.message, 'Unsupported version 255')
      })
  })

  it('shall fail on bad digest', function () {
    const v = new Vault(password)
    return v.decrypt(vaultBadDigest)
      .then(() => {
        ok(false, 'shall not reach here')
      })
      .catch(err => {
        strictEqual(err.message, 'Unsupported digest')
      })
  })

  it('shall fail on bad iterations', function () {
    const v = new Vault(password)
    return v.decrypt(vaultBadIterations)
      .then(() => {
        ok(false, 'shall not reach here')
      })
      .catch(err => {
        strictEqual(err.message, 'Decrypt failed')
      })
  })

  it('shall fail on bad salt', function () {
    const v = new Vault(password)
    return v.decrypt(vaultBadSalt)
      .then(() => {
        ok(false, 'shall not reach here')
      })
      .catch(err => {
        if (nodeVersion[0] >= 17) {
          strictEqual(err.message, 'error:0308010C:digital envelope routines::unsupported')
        } else {
          strictEqual(err.message, 'Decrypt failed')
        }
      })
  })

  it('shall fail on bad box', function () {
    const v = new Vault(password)
    return v.decrypt(vaultBadBox)
      .then(() => {
        ok(false, 'shall not reach here')
      })
      .catch(err => {
        strictEqual(err.message, 'Decrypt failed')
      })
  })
})
