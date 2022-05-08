const { Vault } = require('./Vault')
const { deleteWhiteSpace, splitLines, wrapEncrypted } = require('./utils.js')

const RE_DECRYPT = /\bVAULT_NACL\(([A-Za-z0-9/+\s]{37,}[=\s]{0,5})\)(?!VAULT_NACL)/gm
const RE_ENCRYPT = /\bVAULT_NACL\(([^)]+?)\)VAULT_NACL(?!\))/gm

class EncDecSync {
  /**
   * @param {string} password
   * @param {object} opts
   * @param {string} [opts.digest='sha256']
   * @param {number} [opts.iterations=310000]
   * @param {BufferEncoding} [opts.inputEncoding='utf8']
   * @param {BufferEncoding} [opts.outputEncoding='base64']
   */
  constructor (password, opts = {}) {
    this._vault = new Vault(password, opts)
    this._keys = []
    this._doSplit = false
    this._hasVaults = false
  }

  clear () {
    this._keys = []
    this._vault.clear()
  }

  /**
   * @param {any} values
   * @return {any}
   */
  decrypt (values) {
    this._keys = []
    return this._traverse(values)
  }

  /**
   * @param {any} values
   * @return {any}
   */
  encrypt (values) {
    this._keys = []
    return this._traverse(values, { isEncMode: true })
  }

  /**
   * @param {string} str
   * @return {string}
   */
  encryptString (str, { doSplit = true } = {}) {
    if (typeof str !== 'string') throw new TypeError('string expected')
    this._doSplit = !!doSplit
    return this.encrypt(`VAULT_NACL(${str})VAULT_NACL`)
  }

  /**
   * @param {any} values
   * @param {Vault|String} [newVault] - new password/vault for re-encryption
   * @return {any}
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

  /**
   * @param {any} values
   * @return {boolean}
   */
  check (values) {
    this._hasVaults = false
    this._keys = []
    this._traverse(values, { isCheckMode: true })
    return this._hasVaults
  }

  /**
   * @private
   * @param {any} obj
   * @param {object} [param1]
   * @param {boolean} [param1.isCheckMode]
   * @param {boolean} [param1.isEncMode]
   * @param {Vault} [param1.newVault]
   * @param {any} [param1.visited]
   * @returns {any}
   */
  _traverse (obj, { isCheckMode = false, isEncMode = false, newVault, visited = [] } = {}) {
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

  /**
   * @private
   * @param {string} str
   * @param {object} [param1 ]
   * @param {Vault} [param1.newVault]
   * @returns {string}
   */
  _replaceEncMode (str = '', { newVault } = {}) {
    const decoded = []
    let doSplit = this._doSplit

    // @ts-ignore
    str.replace(RE_DECRYPT, (m, enc) => {
      if (/\s/.test(enc)) doSplit = true
      decoded.push(this._vault.decryptSync(deleteWhiteSpace(enc)))
    })

    if (newVault) { // re-encrypt
      for (let i = 0; i < decoded.length; i++) {
        decoded[i] = newVault.encryptSync(decoded[i])
      }
      let i = 0
      str = str.replace(RE_DECRYPT, () => wrapEncrypted(
        splitLines(decoded[i++], doSplit),
        doSplit
      ))
    }

    const vault = newVault || this._vault
    return str.replace(RE_ENCRYPT, (m, enc) => wrapEncrypted(
      splitLines(vault.encryptSync(enc), doSplit),
      doSplit
    ))
  }

  _replace (str) {
    try {
      return str.replace(RE_DECRYPT, (m, enc) => this._vault.decryptSync(deleteWhiteSpace(enc)))
    } catch (/** @type {any} */err) {
      if (err.message === 'Decrypt failed' && this._keys.length) {
        throw new Error(`Decrypt failed at "${this._keys.join('.')}"`)
      } else {
        throw err
      }
    }
  }
}

module.exports = {
  EncDecSync
}
