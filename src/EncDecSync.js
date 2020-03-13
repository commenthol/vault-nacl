const { Vault } = require('./Vault')

const RE_DECRYPT = /\bVAULT_NACL\(([A-Za-z0-9/+\s]{37,}={0,3})\)(?!VAULT_NACL)/gm
const RE_ENCRYPT = /\bVAULT_NACL\((.+?)\)VAULT_NACL(?!\))/gm

const wrapEncrypted = str => `VAULT_NACL(${str})`

class EncDecSync {
  /**
   * @param {string} [digest='sha256']
   * @param {number} [iterations=10000]
   * @param {string} [inputEncoding='utf8']
   * @param {string} [outputEncoding='base64']
   */
  constructor (password, opts = {}) {
    this._vault = new Vault(password, opts)
    this._keys = []
  }

  clear () {
    this._keys = []
    this._vault.clear()
  }

  decrypt (values) {
    this._keys = []
    return this._traverse(values)
  }

  encrypt (values) {
    this._keys = []
    return this._traverse(values, { isEncMode: true })
  }

  /**
   * @param {Vault|String} [newVault] - new password/vault for re-encryption
   */
  rekey (values, newVault) {
    this._keys = []
    if (typeof newVault === 'string') {
      newVault = new Vault(newVault)
    }
    if (newVault && !(newVault instanceof Vault)) {
      throw new Error('Need instanceof Vault')
    }
    return this._traverse(values, { isEncMode: true, newVault })
  }

  check (values) {
    this._hasVaults = false
    this._keys = []
    this._traverse(values, { isCheckMode: true })
    return this._hasVaults
  }

  _traverse (obj, { isCheckMode, isEncMode, newVault, visited = [] } = {}) {
    const idx = visited.indexOf(obj) // circularity check
    if (idx !== -1) {
      return obj
    } else {
      switch (toString.call(obj)) {
        case '[object Object]': {
          Object.keys(obj).forEach((key) => {
            if (key !== '__proto__') {
              visited.push(obj)
              this._keys.push(key)
              obj[key] = this._traverse(obj[key], { isCheckMode, isEncMode, newVault, visited })
              this._keys.pop()
              visited.pop(obj)
            }
          })
          return obj
        }
        case '[object Array]': {
          return obj.map((item, i) => {
            this._keys.push(`[${i}]`)
            const val = this._traverse(item, { isCheckMode, isEncMode, newVault, visited })
            this._keys.pop()
            return val
          })
        }
        case '[object String]': {
          if (isCheckMode && (RE_DECRYPT.test(obj) || RE_ENCRYPT.test(obj))) {
            this._hasVaults = true
            return obj
          }
          return isEncMode
            ? this._replaceEncMode(obj, { newVault })
            : this._replace(obj)
        }
        default: {
          return obj
        }
      }
    }
  }

  _replaceEncMode (str = '', { newVault } = {}) {
    const decoded = []
    str.replace(RE_DECRYPT, (m, enc) => decoded.push(this._vault.decryptSync(enc)))

    if (newVault) { // re-encrypt
      for (let i = 0; i < decoded.length; i++) {
        decoded[i] = newVault.encryptSync(decoded[i])
      }
      let i = 0
      str = str.replace(RE_DECRYPT, () => wrapEncrypted(decoded[i++]))
    }
    const vault = newVault || this._vault
    return str.replace(RE_ENCRYPT, (m, enc) => wrapEncrypted(vault.encryptSync(enc)))
  }

  _replace (str = '') {
    try {
      return str.replace(RE_DECRYPT, (m, enc) => this._vault.decryptSync(enc))
    } catch (e) {
      if (e.message === 'Decrypt failed' && this._keys.length) {
        throw new Error(`Decrypt failed at "${this._keys.join('.')}"`)
      } else {
        throw e
      }
    }
  }
}

module.exports = {
  EncDecSync
}
