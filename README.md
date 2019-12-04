# jose-x25519-ecdh

This is a plugin for the [`jose`][jose] package that implements Key Agreement with Elliptic Curve
Diffie-Hellman Ephemeral Static for `X25519` OKP keys.

## Why a plugin?

1) It's backed by libsodium instead of node crypto, unfortunately Node.js does not support this ECDH
yet
2) It'll get deprecated once Node.js
[fills the missing feature gap](https://github.com/nodejs/node/issues/26626) and the functionality
will be implemented in the jose module instead

## Usage

Installing

```console
npm install jose // jose ^1.16.0 declared as a peer dependency
npm install jose-x25519-ecdh
```

```js
const jose = require('jose')
const x25519 = require('jose-x25519-ecdh')

(async () => {
  await x25519 // wait for libsodium to be ready!

  {
    const key = jose.JWK.generateSync('OKP', 'X25519')
    console.log(key.algorithms())
    console.log(jose.JWE.encrypt('foobar', key))
  }
})()
```

**Note:** X25519 OKP keys are only supported in Node.js runtime >= 12.0.0 and are not supported in
electron due to BoringSSL not having the curve implemented.

Have a question about using `jose`? - [ask][ask].  
Found a bug? - [report it][bug].  
Missing a feature? - If it wasn't already discussed before, [ask for it][suggest-feature].  
Found a vulnerability? - Reach out to us via email first, see [security vulnerability disclosure][security-vulnerability].

## Support

If you or your business use `jose`, please consider becoming a [sponsor][support-sponsor] so I can continue maintaining it and adding new features carefree.

[ask]: https://github.com/panva/jose-x25519-ecdh/issues/new?labels=question&template=question.md&title=question%3A+
[bug]: https://github.com/panva/jose-x25519-ecdh/issues/new?labels=bug&template=bug-report.md&title=bug%3A+
[suggest-feature]: https://github.com/panva/jose-x25519-ecdh/issues/new?labels=enhancement&template=feature-request.md&title=proposal%3A+
[security-vulnerability]: https://github.com/panva/jose-x25519-ecdh/issues/new?template=security-vulnerability.md
[support-sponsor]: https://github.com/sponsors/panva
[jose]: https://github.com/panva/jose
