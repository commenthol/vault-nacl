const { Vault } = require('./Vault')
const { deleteWhiteSpace, splitLines, wrapEncrypted } = require('./utils.js')

const RE_DECRYPT = /\bVAULT_NACL\(([A-Za-z0-9/+\s]{37,}[=\s]{0,5})\)(?!VAULT_NACL)/m
const RE_ENCRYPT = /\bVAULT_NACL\(([^)]+?)\)VAULT_NACL(?!\))/m

class EncDec {
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
   * @return {Promise<any>}
   */
  decrypt (values) {
    this._keys = []
    return this._traverse(values)
  }

  /**
   * @param {any} values
   * @return {Promise<any>}
   */
  encrypt (values) {
    this._keys = []
    return this._traverse(values, { isEncMode: true })
  }

  /**
   * @param {string} str
   * @return {Promise<string>}
   */
  encryptString (str, { doSplit = true } = {}) {
    if (typeof str !== 'string') throw new TypeError('string expected')
    this._doSplit = !!doSplit
    return this.encrypt(`VAULT_NACL(${str})VAULT_NACL`)
  }

  /**
   * @param {any} values
   * @param {Vault|String} [newVault] - new password/vault for re-encryption
   * @return {Promise<any>}
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
   * @return {Promise<boolean>}
   */
  async check (values) {
    this._hasVaults = false
    this._keys = []
    await this._traverse(values, { isCheckMode: true })
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
   * @returns {Promise<any>}
   */
  async _traverse (obj, { isCheckMode, isEncMode, newVault, visited = [] } = {}) {
    const idx = visited.indexOf(obj) // circularity check
    if (idx !== -1) {
      return obj
    } else {
      switch (toString.call(obj)) {
        case '[object Object]': {
          for (const key of Object.keys(obj)) {
            if (key !== '__proto__') {
              visited.push(obj)
              this._keys.push(key)
              obj[key] = await this._traverse(obj[key], { isCheckMode, isEncMode, newVault, visited })
              this._keys.pop()
              visited.pop(obj)
            }
          }
          return obj
        }
        case '[object Array]': {
          const arr = []
          for (let i = 0; i < obj.length; i++) {
            const item = obj[i]
            this._keys.push(`[${i}]`)
            const val = await this._traverse(item, { isCheckMode, isEncMode, newVault, visited })
            this._keys.pop()
            arr.push(val)
          }
          return arr
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
   * @returns {Promise<string>}
   */
  async _replaceEncMode (str = '', { newVault } = {}) {
    const decoded = []
    let doSplit = this._doSplit

    await replace(RE_DECRYPT, str, async (enc) => {
      if (/\s/.test(enc)) doSplit = true
      decoded.push(await this._vault.decrypt(deleteWhiteSpace(enc)))
    })

    if (newVault) { // re-encrypt
      for (let i = 0; i < decoded.length; i++) {
        decoded[i] = newVault.encryptSync(decoded[i])
      }
      let i = 0
      str = str.replace(new RegExp(RE_DECRYPT.source, 'gm'), () => wrapEncrypted(
        splitLines(decoded[i++], doSplit),
        doSplit
      ))
    }

    const vault = newVault || this._vault
    return replace(RE_ENCRYPT, str, async (enc) => wrapEncrypted(
      splitLines(await vault.encrypt(enc), doSplit),
      doSplit
    ))
  }

  _replace (str) {
    try {
      return replace(RE_DECRYPT, str, (enc) => this._vault.decrypt(deleteWhiteSpace(enc)))
    } catch (/** @type {any} */err) {
      if (err.message === 'Decrypt failed' && this._keys.length) {
        throw new Error(`Decrypt failed at "${this._keys.join('.')}"`)
      } else {
        throw err
      }
    }
  }
}

async function replace (regex, str = '', fn) {
  let out = ''
  for (;;) {
    const m = regex.exec(str)
    if (!m) {
      out += str
      break
    } else {
      out += str.slice(0, m.index)
      out += await fn(m[1])
      str = str.slice(m.index + m[0].length)
    }
  }
  return out
}

module.exports = {
  EncDec
}
