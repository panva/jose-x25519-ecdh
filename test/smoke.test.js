const test = require('ava')
const crypto = require('crypto')

let jose
let errors

test.before(async t => {
  jose = require('jose')
  errors = jose.errors
  await require('../lib')
})

test('all OKP X25519 key JWE functionality', t => {
  const key = jose.JWK.generateSync('OKP', 'X25519', { use: 'enc' })
  const key2 = jose.JWK.generateSync('OKP', 'X25519', { use: 'enc' })

  key.algorithms('deriveKey').forEach((alg) => {
    jose.JWE.decrypt(jose.JWE.encrypt('foo', key, { alg }), key)
    t.throws(() => {
      jose.JWE.decrypt(jose.JWE.encrypt('foo', key, { alg }), key2)
    }, { instanceOf: errors.JWEDecryptionFailed, code: 'ERR_JWE_DECRYPTION_FAILED' })
    t.throws(() => {
      const jwe = jose.JWE.encrypt.flattened('foo', key, { alg })
      jwe.tag = crypto.randomBytes(11).toString('hex')
      jose.JWE.decrypt(jwe, key)
    }, { instanceOf: errors.JWEDecryptionFailed, code: 'ERR_JWE_DECRYPTION_FAILED' })
    t.throws(() => {
      const jwe = jose.JWE.encrypt.flattened('foo', key, { alg })
      jwe.iv = crypto.randomBytes(jwe.iv.length / 2).toString('hex')
      jose.JWE.decrypt(jwe, key)
    }, { instanceOf: errors.JWEDecryptionFailed, code: 'ERR_JWE_DECRYPTION_FAILED' })
  })
})
