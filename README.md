# vault-nacl

> A symmetric encrypted vault using [tweetnacl][] elliptic curves

[![NPM version](https://badge.fury.io/js/vault-nacl.svg)](https://www.npmjs.com/package/vault-nacl/)

<!-- [![Build Status](https://secure.travis-ci.org/commenthol/vault-nacl.svg?branch=master)](https://travis-ci.org/commenthol/vault-nacl) -->

Allows to symmetrically encrypt dedicated values in a configuration file,
or the complete file itself, using one password.

Implements [xsalsa20-poly1305 secretbox](https://www.npmjs.com/package/tweetnacl#secret-key-authenticated-encryption-secretbox)
and [pbkdf2](https://tools.ietf.org/html/rfc8018) with different digests for
safe encryption.

Default is sha256 (310000 iterations) which can be changed to 'sha384' or 'sha512' (120000 iterations).

Uses `VAULT_NACL(...)` markers with Base64 encrypted secret inside the vault to
identify encrypted values for decryption.

New values attributed with `VAULT_NACL(...)VAULT_NACL` are used for later encryption.

Choose the CLI or API to fit your usecase.

## toc

<!-- !toc (minlevel=2 omit="toc") -->

* [installation](#installation)
* [usage cli](#usage-cli)
* [api](#api)
  * [enc-decrypt](#enc-decrypt)
  * [vault](#vault)
* [internals](#internals)
* [license](#license)

<!-- toc! -->

## installation

```
npm install --save vault-nacl
```

## usage cli

_Encrypt single value_

```bash
$ vault-nacl encrypt
✔ Vault password · ***************
✔ Confirm Vault password · ***************
✔ Secret · *********
VAULT_NACL(AQAQJwAA6mwY4MkxGLKi4T0IZaOeh5Ul7iUv7SRzYK50xQR8iYNOXZQ9+lmSSb8PYkkk5zITgbCC/HbAJJ2B)
```

_Decrypt single value_

```bash
$ vault-nacl decrypt
✔ Vault password · ***************
✔ Vault · VAULT_NACL(AQAQJwAA6mwY4MkxGLKi4T0IZaOeh5Ul7iUv7SRzYK50xQR8iYNOXZQ9+lmSSb8PYkkk5zITgbCC/HbAJJ2B)
my secret
```

_Encrypt a configuration file_

```bash
echo {"secret":"VAULT_NACL(my secret hidden value)VAULT_NACL"} > config.json

$ vault-nacl encrypt config.json
✔ Vault password · ***************
✔ Confirm Vault password · ***************

$ cat config.json
{"secret":"VAULT_NACL(AQAQJwAA+XJjGfdtC8jCt7xsWoPBCz2p/qs5MXpzmsqV5jFGCm6xfZgKcADzu3glf1z/5KxKaFFJbtCvX5rAqh/jq3UhRsMHHirldw==)"}
```

_Decrypt a configuration file_

```bash
$ vault-nacl decrypt config.json
✔ Vault password · ***************
✔ Confirm Vault password · ***************
{"secret":"my secret hidden value"}
```

See `vault-nacl --help` for complete list of options.

## api

### enc-decrypt

`EncDecSync` handles `VAULT_NACL(...)` encoded strings in strings or objects.

> NOTE: This function is blocking.

_encrypt_

```js
const { EncDecSync } = require('vault-nacl')
const password = '$€creT'
const secret = { mySecret: `VAULT_NACL(a $€Cr3T secret)VAULT_NACL` }

const encdec = new EncDecSync(password)
const result = encdec.encrypt(secret)
//>  { mySecret: 'VAULT_NACL(AQAQJwAA+CWBR7...+qAo=)' }

encdec.decrypt(result)
//> { mySecret: 'a $€Cr3T secret' }
```

### vault

`Vault` provides the interface to en- and decryption.

_asynchronous_

```js
const { Vault } = require('vault-nacl')

const password = '$€creT'

async function main() {
  const vault = new Vault(password)

  const ciphertext = await vault.encrypt('my secret message')
  const orginal = await vault.decrypt(ciphertext)
  //> 'my secret message'

  vault.clear() // clear password
}
main()
```

_synchronous_

This example uses a different digest and iterations:

```js
const { Vault } = require('vault-nacl')

const password = '$€creT'

const vault = new Vault(password, { digest: 'sha512', iterations: 20000 })
const ciphertext = vault.encryptSync('my secret message')
const orginal = vault.decryptSync(ciphertext)
//> 'my secret message'

vault.clear() // clear password
```

## internals

Format of the base64 encrypted secret:

**Version 1**

| 1 Byte    | 1Byte  | 4Bytes     | 32Bytes | n-Bytes      |
| --------- | ------ | ---------- | ------- | ------------ |
| version=1 | digest | iterations | salt    | boxed secret |

- digest: digest index. See src/Vault.js DIGESTS
  0='sha256', 1='sha384', 2='sha512', 3='ripemd', 4='whirlpool'
- iterations: Number of iterations. Default 10000
- salt: Used salt for key derivation

## license

MIT licensed

[tweetnacl]: https://npmjs.com/package/tweetnacl
