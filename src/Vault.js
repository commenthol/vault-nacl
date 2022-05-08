const { promisify } = require('util')
const crypto = require('crypto')
const nacl = require('tweetnacl/nacl-fast')

const pbkdf2 = promisify(crypto.pbkdf2)

const VERSION = 1
const PASSWORD = Symbol('PASSWORD')
const NONCE_LEN = nacl.box.nonceLength
const KEY_LEN = nacl.box.secretKeyLength
const DIGESTS = [
  'sha256',
  'sha384',
  'sha512',
  'ripemd',
  'whirlpool'
]

const digestToId = (digest) => Buffer.from([DIGESTS.indexOf(digest)])
const idToDigest = (id) => DIGESTS[id[0]]

const numToBuffer = (number) => {
  const buf = Buffer.alloc(4)
  buf.writeUInt32LE(number)
  return buf
}
const bufferToNum = (buf) => buf.readUInt32LE()

class Vault {
  constructor (password, {
    digest = 'sha256',
    iterations,
    inputEncoding = 'utf8',
    outputEncoding = 'base64'
  } = {}) {
    // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    if (!iterations) {
      iterations = digest === 'sha512'
        ? 120000
        : 310000
    }

    Object.assign(this, {
      digest,
      iterations,
      inputEncoding,
      outputEncoding
    })

    Object.defineProperty(this, PASSWORD, { value: password, writable: true })
  }

  clear () {
    Object.defineProperty(this, PASSWORD, { value: undefined })
  }

  _derivedKeySync ({ salt, iterations, digest }) {
    if (!this[PASSWORD]) throw new Error('No password')
    if (!DIGESTS.includes(digest)) throw new Error('Unsupported digest')
    const derivedKey = crypto.pbkdf2Sync(this[PASSWORD], salt, iterations, NONCE_LEN + KEY_LEN, digest)
    let tmp = 0
    const nonce = derivedKey.slice(tmp, tmp += NONCE_LEN)
    const key = derivedKey.slice(tmp, tmp += KEY_LEN)
    return {
      nonce,
      key
    }
  }

  _joinV1 ({ salt, digest, iterations, box }) {
    return Buffer.concat([
      Buffer.from([VERSION]), // 1 byte
      digestToId(digest), // 1 byte
      numToBuffer(iterations), // 4 byte
      salt, // KEY_LEN bytes
      box
    ])
  }

  _sliceV1 (buf) {
    let tmp = 0
    const version = buf.slice(tmp, tmp += 1)[0]
    const digest = idToDigest(buf.slice(tmp, tmp += 1))
    const iterations = bufferToNum(buf.slice(tmp, tmp += 4))
    const salt = buf.slice(tmp, tmp += KEY_LEN)
    const box = buf.slice(tmp)
    if (version > VERSION) throw new Error(`Unsupported version ${version}`)
    // console.log(digest, iterations, version)
    return { salt, digest, iterations, box, version }
  }

  _enc ({ salt, digest, iterations, msgBuffer, nonce, key }) {
    const box = nacl.secretbox(msgBuffer, nonce, key)
    const buf = this._joinV1({ salt, digest, iterations, box })
    return buf.toString(this.outputEncoding)
  }

  _dec ({ box, nonce, key }) {
    try {
      const msgBuffer = Buffer.from(nacl.secretbox.open(box, nonce, key))
      return msgBuffer.toString(this.inputEncoding)
    } catch (e) {
      throw new Error('Decrypt failed')
    }
  }

  encryptSync (message) {
    const msgBuffer = Buffer.from(message, this.inputEncoding)
    const salt = nacl.randomBytes(KEY_LEN)
    const { digest, iterations } = this
    const { nonce, key } = this._derivedKeySync({ salt, digest, iterations })
    return this._enc({ salt, digest, iterations, msgBuffer, nonce, key })
  }

  decryptSync (message) {
    const buf = Buffer.from(message, this.outputEncoding)
    const { salt, digest, iterations, box } = this._sliceV1(buf)
    const { nonce, key } = this._derivedKeySync({ salt, digest, iterations })
    return this._dec({ box, nonce, key })
  }

  async _derivedKey ({ salt, iterations, digest }) {
    if (!this[PASSWORD]) throw new Error('No password')
    if (!DIGESTS.includes(digest)) throw new Error('Unsupported digest')
    const derivedKey = await pbkdf2(this[PASSWORD], salt, iterations, NONCE_LEN + KEY_LEN, digest)
    let tmp = 0
    const nonce = derivedKey.slice(tmp, tmp += NONCE_LEN)
    const key = derivedKey.slice(tmp, tmp += KEY_LEN)
    return {
      nonce,
      key
    }
  }

  async encrypt (message) {
    const msgBuffer = Buffer.from(message, this.inputEncoding)
    const salt = nacl.randomBytes(KEY_LEN)
    const { digest, iterations } = this
    const { nonce, key } = await this._derivedKey({ salt, digest, iterations })
    return this._enc({ salt, digest, iterations, msgBuffer, nonce, key })
  }

  async decrypt (message) {
    const buf = Buffer.from(message, this.outputEncoding)
    const { salt, digest, iterations, box } = this._sliceV1(buf)
    const { nonce, key } = await this._derivedKey({ salt, digest, iterations })
    return this._dec({ box, nonce, key })
  }
}

module.exports = { Vault }
