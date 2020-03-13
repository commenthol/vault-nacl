#!/usr/bin/env node

/* eslint-disable no-console */

const fs = require('fs')
const path = require('path')
const chalk = require('chalk')
const { prompt } = require('enquirer')
const { EncDecSync, Vault, readPwdFileSync } = require('..')

const MSG_PASSWORD = 'Vault password'
const MSG_PASSWORD_CONFIRM = 'Confirm Vault password'
const MSG_NEW_PASSWORD = 'New Vault password'
const MSG_NEW_PASSWORD_CONFIRM = 'Confirm new Vault password'
const ERROR_PASSWORD_MATCH = 'Error: Passwords need to match!'
const ERROR_COMMAND = 'Missing action!'
const ERROR_PASSWORD = 'Empty password!'
const ERROR_ITERATIONS = 'iterations is not a Number!'

async function promtPassword (message, password1) {
  const { password } = await prompt({
    type: 'password',
    name: 'password',
    message,
    validate: (inp) => !password1 || password1 === inp || ERROR_PASSWORD_MATCH
  })
  return password
}

function argv () {
  const argv = process.argv.slice(2)
  const cmd = { files: [] }

  while (argv.length) {
    const arg = argv.shift()
    switch (arg) {
      case '-h':
      case '--help':
        cmd.help = true
        break
      case '--version':
        cmd.version = true
        break
      case 'encrypt':
      case 'decrypt':
      case 'rekey':
        cmd.action = arg
        break
      case '-p':
      case '--password':
        cmd.password = argv.shift()
        break
      case '--new-password':
        cmd.newPassword = argv.shift()
        break
      case '--password-file':
        cmd.passwordFile = argv.shift()
        break
      case '--new-password-file':
        cmd.newPasswordFile = argv.shift()
        break
      case '--digest':
        cmd.digest = argv.shift()
        break
      case '--iterations':
        cmd.iterations = Number(argv.shift())
        if (!isNaN(cmd.iterations)) {
          throw new Error(ERROR_ITERATIONS)
        }
        break
      case '-o':
      case '--output':
        cmd.output = path.resolve(process.cwd(), argv.shift())
        break
      default:
        cmd.files.push(path.resolve(process.cwd(), arg))
        break
    }
  }
  return cmd
}

async function ask (cmd) {
  if (!cmd.password && !cmd.passwordFile) {
    const password1 = await promtPassword(MSG_PASSWORD)
    if (cmd.action === 'encrypt') {
      await promtPassword(MSG_PASSWORD_CONFIRM, password1)
    }
    cmd.password = password1
  }
  if (cmd.action === 'rekey' && !cmd.newPasswordFile && !cmd.newPassword) {
    const { password1 } = await prompt({
      type: 'password',
      name: 'password1',
      message: MSG_NEW_PASSWORD
    })
    await prompt({
      type: 'password',
      name: 'password2',
      message: MSG_NEW_PASSWORD_CONFIRM,
      validate: (inp) => password1 === inp || ERROR_PASSWORD_MATCH
    })
    cmd.newPassword = password1
  }
}

const readFile = (filename) => fs.readFileSync(filename, 'utf8')
const writeFile = (filename, data) => fs.writeFileSync(filename, data, 'utf8')

function version () {
  console.log('v' + require('../package.json').version)
}

function help () {
  console.log(fs.readFileSync(path.resolve(__dirname, '..', 'man', 'vault-nacl.txt'), 'utf8'))
}

async function main () {
  const cmd = argv()

  if (cmd.help) {
    help()
  } else if (cmd.version) {
    version()
  } else if (!cmd.action) {
    throw new Error(ERROR_COMMAND)
  // } else if (!cmd.files.length) {
  //   console.error(chalk.red(ERROR_FILENAME))
  //   process.exit(2)
  } else {
    await ask(cmd)

    let newVault

    if (!cmd.password && cmd.passwordFile) {
      cmd.password = readPwdFileSync(cmd.passwordFile)
      if (!cmd.password) throw new Error(ERROR_PASSWORD)
    }
    if (!cmd.newPassword && cmd.newPasswordFile) {
      cmd.newPassword = readPwdFileSync(cmd.newPasswordFile)
    }
    const encdec = new EncDecSync(cmd.password)

    if (!cmd.files.length) {
      if (cmd.action === 'encrypt') {
        const data = await promtPassword('Secret')
        const _data = encdec.encrypt(`VAULT_NACL(${data})VAULT_NACL`)
        console.log(_data)
        return
      } else if (cmd.action === 'decrypt') {
        const { data } = await prompt({
          type: 'input',
          name: 'data',
          message: 'Vault'
        })
        const _data = encdec.decrypt(data)
        console.log(_data)
        return
      }
    }

    cmd.files.forEach(filename => {
      const data = readFile(filename)
      switch (cmd.action) {
        case 'decrypt': {
          const _data = encdec.decrypt(data)
          if (cmd.output && cmd.files.length === 1) {
            fs.writeFileSync(cmd.output, _data, 'utf8')
          } else {
            console.log(_data) // print decrypted data to stdout
          }
          break
        }
        case 'encrypt': {
          const _data = encdec.encrypt(data)
          writeFile(filename, _data)
          break
        }
        case 'rekey': {
          const { digest, iterations } = cmd
          newVault = new Vault(cmd.newPassword, { digest, iterations })
          const _data = encdec.rekey(data, newVault)
          writeFile(filename, _data)
          break
        }
      }
    })
  }
}

main().catch(err => {
  console.error(chalk.red('Error: ' + err.message))
  process.exit(1)
})
