secp256k1
=====

[![CircleCI](https://circleci.com/gh/sammyne/secp256k1.svg?style=svg)](https://circleci.com/gh/sammyne/secp256k1) 
[![codecov](https://codecov.io/gh/sammyne/secp256k1/branch/master/graph/badge.svg)](https://codecov.io/gh/sammyne/secp256k1) 
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/sammyne/secp256k1/blob/master/LICENSE) 
[![GoDoc](https://godoc.org/github.com/sammyne/secp256k1?status.png)](http://godoc.org/github.com/sammyne/secp256k1)

Package secp256k1 implements elliptic curve cryptography needed for working with
Bitcoin (secp256k1 only for now). It is designed so that it may be used with the
standard crypto/ecdsa packages provided with go.  A comprehensive suite of test
is provided to ensure proper functionality.  Package secp256k1 was originally based
on work from ThePiachu which is licensed under the same terms as Go, but it has
signficantly diverged since then.  The btcsuite developers original is licensed
under the liberal ISC license.

This package is one of the core packages from btcd, an alternative full-node
implementation of bitcoin which is under active development by Conformal.
Although it was primarily written for btcd, this package has intentionally been
designed so it can be used as a standalone package for any projects needing to
use secp256k1 elliptic curve cryptography.

## Documentation

Full `go doc` style documentation for the project can be viewed online without
installing this package by using the GoDoc site
[here](http://godoc.org/github.com/sammyne/secp256k1).

You can also view the documentation locally once the package is installed with
the `godoc` tool by running `godoc -http=":6060"` and pointing your browser to
http://localhost:6060/pkg/github.com/sammyne/secp256k1

## Installation

```bash
$ go get github.com/sammyne/secp256k1
```

## Examples

* [Sign Message](http://godoc.org/github.com/sammyne/secp256k1#example-package--SignMessage)  
  Demonstrates signing a message with a secp256k1 private key that is first
  parsed form raw bytes and serializing the generated signature.

* [Verify Signature](http://godoc.org/github.com/sammyne/secp256k1#example-package--VerifySignature)  
  Demonstrates verifying a secp256k1 signature against a public key that is
  first parsed from raw bytes.  The signature is also parsed from raw bytes.

## GPG Verification Key

All official release tags are signed by Conformal so users can ensure the code
has not been tampered with and is coming from the btcsuite developers.  To 
verify the signature perform the following:

- Download the public key from the Conformal website at
  https://opensource.conformal.com/GIT-GPG-KEY-conformal.txt

- Import the public key into your GPG keyring:
  ```bash
  gpg --import GIT-GPG-KEY-conformal.txt
  ```

- Verify the release tag with the following command where `TAG_NAME` is a
  placeholder for the specific tag:
  ```bash
  git tag -v TAG_NAME
  ```

## License

Package secp256k1 is licensed under the [copyfree](http://copyfree.org) ISC License
except for secp256k1.go and secp256k1_test.go which is under the same license as Go.

## Advanced  
### Renew `secp256k1.go`  
```bash
go run -tags=gensecp256k1 genprecomps.go 
```

## TODO
- catch up with that of [btcd/btcec](https://github.com/btcsuite/btcd/commits/master/btcec)