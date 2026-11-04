// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package wimseagent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// RFC 9864 deprecated the "EdDSA" algorithm identifier and instead recommended
// the usage of fully qualified names.
const algEd25519 jose.SignatureAlgorithm = "Ed25519"

func curveName(c elliptic.Curve) string {
	if c == nil || c.Params() == nil {
		return "<nil>"
	}
	return c.Params().Name
}

// defaultJwkAlgorithm returns the default [jose.SignatureAlgorithm] for the
// given [crypto.PublicKey] type, to be used when creating a public JWK.
func defaultJwkAlgorithm(pub crypto.PublicKey) (jose.SignatureAlgorithm, error) {
	switch pub := pub.(type) {
	case ed25519.PublicKey:
		return algEd25519, nil
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		default:
			return "", fmt.Errorf("unsupported jwk: ecdsa curve %s", curveName(pub.Curve))
		}
	case *rsa.PublicKey:
		// PSS has better security properties and PKCS#v1.5 is disallowed by
		// NIST. We use SHA-512 because that is the only form that httpsig
		// supports.
		// TODO: We should probably not have this kind of loose coupling
		// between httpsig, wimseagent, and cryptoext...
		return jose.PS512, nil
	}
	return "", fmt.Errorf("unsupported jwk: public key type %T", pub)
}

// toJwkPublic takes a [crypto.PublicKey] and converts it to a
// [jose.JSONWebKey] with the default algorithm for the key type set in "alg".
func toJwkPublic(pub crypto.PublicKey) (jose.JSONWebKey, error) {
	alg, err := defaultJwkAlgorithm(pub)
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("get default jwk.alg: %w", err)
	}
	return jose.JSONWebKey{
		Algorithm: string(alg),
		Key:       pub,
	}, nil
}

// jwkSignerOpts returns the [crypto.SignerOpts] that need to be used to match
// the public key description in [jose.JSONWebKey].
//
// NOTE: Users should ensure that the JWK passed here actually matches the
// [crypto.Signer] key they plan to use, and that the WIT's jwk.cfg matches the
// public portion.
func jwkSignerOpts(pubJwk jose.JSONWebKey) (crypto.SignerOpts, error) {
	pub := pubJwk.Public().Key
	if pub == nil {
		return nil, fmt.Errorf("jwk is missing key: %#v", pubJwk)
	}

	// Prefer the declared signature algorithm.
	alg := jose.SignatureAlgorithm(pubJwk.Algorithm)
	if alg == "" {
		var err error
		alg, err = defaultJwkAlgorithm(pub)
		if err != nil {
			return nil, fmt.Errorf("get fallback jwk.alg: %w", err)
		}
	}

	switch alg { //nolint:exhaustive // we intentionally only support a subset
	case jose.EdDSA:
		// Technically EdDSA can also refer to Ed448 so make sure we don't
		// return signing options for the wrong signature algorithm.
		if _, ok := pub.(ed25519.PublicKey); !ok {
			return nil, fmt.Errorf("invalid alg %q with non-ed25519 key type: %T", alg, pub)
		}
		fallthrough
	case algEd25519:
		return crypto.Hash(0), nil
	case jose.ES256:
		return crypto.SHA256, nil
	case jose.ES384:
		return crypto.SHA384, nil
	case jose.RS256:
		return crypto.SHA256, nil
	case jose.PS512:
		return &rsa.PSSOptions{
			Hash:       crypto.SHA512,
			SaltLength: rsa.PSSSaltLengthEqualsHash, // matches RFC 9421
		}, nil
	}
	// No need to support stuff that is not supported by httpsig (RFC 9421).
	return nil, fmt.Errorf("unsupported alg %q for signing", alg)
}
