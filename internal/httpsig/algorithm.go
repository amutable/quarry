// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
)

// TODO: These algorithms actually match 1-to-1 to JWT signing algorithms. We
// should almost certainly come up with some unified representation of this
// stuff that can live in cryptoext so we don't need to have one version of
// this silly type-switching here and in wimseagent (and possibly in
// keystore).

// algorithm is an RFC 9421 signature algorithm (section 3.3).
type algorithm struct {
	// name is the RFC 9421 "alg" name
	name string
	// nilRand indicates whether this signature algorithm supports taking a nil
	// [io.Reader] as the random source. (For most algorithms there is only one
	// valid mode but ECDSA signatures can be made safe against bad randomness
	// by RFC 6979 deterministic signatures.)
	nilRand bool
	// signerOpts is the canonical [crypto.SignerOpts] options used for this
	// signature algorithm.
	signerOpts crypto.SignerOpts
	// matchOpts is used to allow [Base.SignRequest] to determine which
	// algorithm matches the [crypto.Signer] and [crypto.SignerOpts]
	// combination provided.
	matchOpts func(crypto.SignerOpts) bool
	// convertSig converts a signature encoded by [crypto.SignMessage] in the
	// "Go format" to the RFC 9421 format. If nil, [algorithm.RecodeSignature]
	// is a no-op.
	convertSig func(sig []byte) ([]byte, error)
}

// SignMessage signs a message using this [algorithm]. This is analogous to
// [crypto.SignMessage] except that the returned signature is in the RFC 9421
// signature format rather than the Go-native one used by [crypto]. The
// provided [crypto.SignerOpts] must be compatible with this algorithm or an
// [ErrUnsupportedSignerOpts] error will be returned.
func (alg *algorithm) SignMessage(signer crypto.Signer, msg []byte, opts crypto.SignerOpts) (rfcSig []byte, err error) {
	switch {
	case opts == nil:
		opts = alg.signerOpts
	case !alg.matchOpts(opts):
		return nil, fmt.Errorf("%w: %T %v for %T", ErrUnsupportedSignerOpts, opts, opts, signer.Public())
	}
	var rnd io.Reader
	if !alg.nilRand {
		// Only use crypto/rand.Reader for algorithms that really need it.
		rnd = rand.Reader
	}
	goSig, err := crypto.SignMessage(signer, rnd, msg, opts)
	if err != nil {
		return nil, err
	}
	rfcSig = goSig
	if alg.convertSig != nil {
		rfcSig, err = alg.convertSig(goSig)
	}
	return rfcSig, err
}

func matchHash(h crypto.Hash) func(crypto.SignerOpts) bool {
	return func(opts crypto.SignerOpts) bool {
		got, ok := opts.(crypto.Hash)
		return ok && got == h
	}
}

// convertEcdsaSig converts an ASN.1 DER ECDSA signature into the fixed-size
// r||s form RFC 9421 section 3.3.4 uses.
func convertEcdsaSig(size int) func([]byte) ([]byte, error) {
	return func(sig []byte) ([]byte, error) {
		var parsed struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(sig, &parsed)
		if err != nil {
			return nil, fmt.Errorf("parse ecdsa signature: %w", err)
		}
		if len(rest) > 0 {
			return nil, fmt.Errorf("parse ecdsa signature: trailing data")
		}
		if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 ||
			parsed.R.BitLen() > size*8 || parsed.S.BitLen() > size*8 {
			return nil, fmt.Errorf("ecdsa signature values out of range")
		}
		out := make([]byte, 2*size)
		parsed.R.FillBytes(out[:size])
		parsed.S.FillBytes(out[size:])
		return out, nil
	}
}

var (
	algEd25519 = &algorithm{
		name:       "ed25519",
		nilRand:    true, // rand is ignored
		signerOpts: crypto.Hash(0),
		matchOpts: func(opts crypto.SignerOpts) bool {
			switch opts := opts.(type) {
			case crypto.Hash:
				return opts == 0
			case *ed25519.Options:
				return opts.Hash == 0 && opts.Context == ""
			}
			return false
		},
		convertSig: func(sig []byte) ([]byte, error) {
			if len(sig) != ed25519.SignatureSize {
				return nil, fmt.Errorf("ed25519 signature is %d bytes, expected %d", len(sig), ed25519.SignatureSize)
			}
			return sig, nil
		},
	}
	algECDSAP256SHA256 = &algorithm{
		name:       "ecdsa-p256-sha256",
		nilRand:    true, // use RFC 6979 deterministic signatures
		signerOpts: crypto.SHA256,
		matchOpts:  matchHash(crypto.SHA256),
		convertSig: convertEcdsaSig(32),
	}
	algECDSAP384SHA384 = &algorithm{
		name:       "ecdsa-p384-sha384",
		nilRand:    true, // use RFC 6979 deterministic signatures
		signerOpts: crypto.SHA384,
		matchOpts:  matchHash(crypto.SHA384),
		convertSig: convertEcdsaSig(48),
	}
	algRSAPSSSHA512 = &algorithm{
		name:       "rsa-pss-sha512",
		signerOpts: &rsa.PSSOptions{Hash: crypto.SHA512, SaltLength: rsa.PSSSaltLengthEqualsHash},
		matchOpts: func(opts crypto.SignerOpts) bool {
			// RFC 9421 section 3.3.1 fixes the salt length at 64 bytes.
			pss, ok := opts.(*rsa.PSSOptions)
			return ok && pss.Hash == crypto.SHA512 &&
				(pss.SaltLength == rsa.PSSSaltLengthEqualsHash || pss.SaltLength == crypto.SHA512.Size())
		},
	}
	algRSAv15SHA256 = &algorithm{
		name:       "rsa-v1_5-sha256",
		signerOpts: crypto.SHA256,
		matchOpts:  matchHash(crypto.SHA256),
	}
)

func curveName(c elliptic.Curve) string {
	if c == nil || c.Params() == nil {
		return "<nil>"
	}
	return c.Params().Name
}

// chooseAlgorithm returns the algorithm for pub and opts, and the options to
// sign with. nil opts selects the key type's default algorithm.
func chooseAlgorithm(pub crypto.PublicKey, opts crypto.SignerOpts) (*algorithm, crypto.SignerOpts, error) {
	var candidates []*algorithm
	switch pub := pub.(type) {
	case ed25519.PublicKey:
		candidates = []*algorithm{algEd25519}
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			candidates = []*algorithm{algECDSAP256SHA256}
		case elliptic.P384():
			candidates = []*algorithm{algECDSAP384SHA384}
		default:
			return nil, nil, fmt.Errorf("%w: ecdsa curve %s", ErrUnsupportedKey, curveName(pub.Curve))
		}
	case *rsa.PublicKey:
		candidates = []*algorithm{algRSAPSSSHA512, algRSAv15SHA256}
	default:
		return nil, nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
	}
	for _, alg := range candidates {
		if opts == nil {
			opts = alg.signerOpts // just use the algorithm default
		}
		if alg.matchOpts(opts) {
			return alg, opts, nil
		}
	}
	return nil, nil, fmt.Errorf("%w: %T %v for %T", ErrUnsupportedSignerOpts, opts, opts, pub)
}
