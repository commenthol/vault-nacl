
const deleteWhiteSpace = str => str.replace(/\s/g, '')

const splitLines = (str, doSplit) => doSplit
  ? str.match(/[^]{1,80}/g).join('\n')
  : str

const wrapEncrypted = (str, doSplit) => doSplit
  ? `VAULT_NACL(\n${str}\n)`
  : `VAULT_NACL(${str})`

module.exports = {
  deleteWhiteSpace,
  splitLines,
  wrapEncrypted
}
