// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package wimseagent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJwkSignerOpts(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate P-256 key")
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err, "generate P-384 key")
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "generate Ed25519 key")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "generate RSA key")
	pss := &rsa.PSSOptions{Hash: crypto.SHA512, SaltLength: rsa.PSSSaltLengthEqualsHash}

	for _, test := range []struct {
		name string
		alg  jose.SignatureAlgorithm
		key  crypto.PublicKey
		want crypto.SignerOpts
	}{
		{"DefaultP256", "", &p256.PublicKey, crypto.SHA256},
		{"DefaultP384", "", &p384.PublicKey, crypto.SHA384},
		{"DefaultEd25519", "", edPub, crypto.Hash(0)},
		{"DefaultRSA", "", &rsaKey.PublicKey, pss},
		{"ES256", jose.ES256, &p256.PublicKey, crypto.SHA256},
		{"ES384", jose.ES384, &p384.PublicKey, crypto.SHA384},
		{"Ed25519", algEd25519, edPub, crypto.Hash(0)},
		{"EdDSA", jose.EdDSA, edPub, crypto.Hash(0)},
		{"RS256", jose.RS256, &rsaKey.PublicKey, crypto.SHA256},
		{"PS512", jose.PS512, &rsaKey.PublicKey, pss},
		{"PrivateKey", "", p256, crypto.SHA256},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := jwkSignerOpts(jose.JSONWebKey{Key: test.key, Algorithm: string(test.alg)})
			require.NoError(t, err, "jwkSignerOpts")
			assert.Equal(t, test.want, got, "signer options")
		})
	}
}

func TestJwkSignerOptsErrors(t *testing.T) {
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err, "generate P-224 key")
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate P-256 key")
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err, "generate P-521 key")

	for _, test := range []struct {
		name string
		jwk  jose.JSONWebKey
	}{
		{"DefaultP521", jose.JSONWebKey{Key: &p521.PublicKey}},
		{"ES512", jose.JSONWebKey{Key: &p521.PublicKey, Algorithm: string(jose.ES512)}},
		{"NoKey", jose.JSONWebKey{}},
		{"UnsupportedCurve", jose.JSONWebKey{Key: &p224.PublicKey}},
		{"EdDSAWithECDSAKey", jose.JSONWebKey{Key: &p256.PublicKey, Algorithm: string(jose.EdDSA)}},
		{"UnsupportedAlg", jose.JSONWebKey{Key: &p256.PublicKey, Algorithm: string(jose.HS256)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := jwkSignerOpts(test.jwk)
			require.Error(t, err, "jwkSignerOpts")
		})
	}
}

func TestToJwkPublic(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate P-256 key")
	jwk, err := toJwkPublic(p256.Public())
	require.NoError(t, err, "toJwkPublic")
	assert.Equal(t, string(jose.ES256), jwk.Algorithm, "alg")
	assert.True(t, jwk.IsPublic(), "public key")

	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err, "generate P-224 key")
	_, err = toJwkPublic(p224.Public())
	require.Error(t, err, "toJwkPublic with an unsupported curve")
	_, err = toJwkPublic("not a key")
	require.Error(t, err, "toJwkPublic with an unsupported type")
}
