const { deprecate } = require('util')

module.exports = (async () => {
  const registry = require('jose/lib/registry')

  if (registry.JWK.OKP.deriveKey['ECDH-ES']) {
    deprecate(() => {}, 'ECDH-ES for OKP keys is already registered in the jose package algorithm registry, skipping...')()
    return
  }

  const { JWK: { generateSync } } = require('jose')

  const derive = require('jose/lib/jwa/ecdh/derive')
  const base64url = require('jose/lib/help/base64url')
  const { KEYOBJECT } = require('jose/lib/help/consts')

  const libsodium = require('libsodium-wrappers')

  const computeSecret = (privateKey, publicKey) => {
    return Buffer.from(libsodium.crypto_scalarmult(base64url.decodeToBuffer(privateKey.d), base64url.decodeToBuffer(publicKey.x)))
  }

  {
    const orig = registry.JWA.keyManagementEncrypt.get('ECDH-ES')
    registry.JWA.keyManagementEncrypt.set('ECDH-ES', (...args) => {
      const [key] = args
      if (key.kty !== 'OKP' || key.crv !== 'X25519') {
        orig(...args)
      } else {
        const [,, { enc }] = args
        const epk = generateSync(key.kty, key.crv)

        const derivedKey = derive(enc, registry.KEYLENGTHS.get(enc), epk, key, undefined, computeSecret)

        return {
          wrapped: derivedKey,
          header: { epk: { kty: key.kty, crv: key.crv, x: epk.x } }
        }
      }
    })
  }

  {
    const orig = registry.JWA.keyManagementDecrypt.get('ECDH-ES')
    registry.JWA.keyManagementDecrypt.set('ECDH-ES', (...args) => {
      const [key] = args
      if (key.kty !== 'OKP' || key.crv !== 'X25519') {
        orig(...args)
      } else {
        const [,, header] = args
        const { enc, epk } = header

        return derive(enc, registry.KEYLENGTHS.get(enc), key, epk, header, computeSecret)
      }
    })
  }

  registry.JWK.OKP.deriveKey['ECDH-ES'] = key => (key.use === 'enc' || key.use === undefined) && key.crv === 'X25519'

  ;[...registry.JWA.keyManagementEncrypt.keys()].filter(x => x.startsWith('ECDH-ES+')).forEach((jwaAlg) => {
    const kwAlg = jwaAlg.substr(-6)

    {
      const orig = registry.JWA.keyManagementEncrypt.get(jwaAlg)
      const keylen = registry.ECDH_DERIVE_LENGTHS.get(jwaAlg)
      const wrapKey = (wrap, key, payload) => {
        const epk = generateSync(key.kty, key.crv)
        const derivedKey = derive(jwaAlg, keylen, epk, key, payload, computeSecret)
        const result = wrap({ [KEYOBJECT]: derivedKey }, payload)
        result.header = result.header || {}
        Object.assign(result.header, { epk: { kty: key.kty, crv: key.crv, x: epk.x } })
        return result
      }

      registry.JWA.keyManagementEncrypt.set(jwaAlg, (...args) => {
        const [key] = args
        if (key.kty !== 'OKP' || key.crv !== 'X25519') {
          orig(...args)
        } else {
          const kwWrap = registry.JWA.keyManagementEncrypt.get(kwAlg)
          const [, payload] = args
          return wrapKey(kwWrap, key, payload)
        }
      })
    }

    {
      const orig = registry.JWA.keyManagementDecrypt.get(jwaAlg)
      const keylen = registry.ECDH_DERIVE_LENGTHS.get(jwaAlg)
      const unwrapKey = (unwrap, key, payload, header) => {
        const { epk } = header
        const derivedKey = derive(jwaAlg, keylen, key, epk, header, computeSecret)

        return unwrap({ [KEYOBJECT]: derivedKey }, payload, header)
      }
      registry.JWA.keyManagementDecrypt.set(jwaAlg, (...args) => {
        const [key] = args
        if (key.kty !== 'OKP' || key.crv !== 'X25519') {
          orig(...args)
        } else {
          const kwUnwrap = registry.JWA.keyManagementDecrypt.get(kwAlg)
          const [, payload, header] = args
          return unwrapKey(kwUnwrap, key, payload, header)
        }
      })
    }

    registry.JWK.OKP.deriveKey[jwaAlg] = key => (key.use === 'enc' || key.use === undefined) && key.crv === 'X25519'
  })

  return libsodium.ready.then(() => undefined)
})()
