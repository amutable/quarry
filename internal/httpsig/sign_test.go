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
	"encoding/base64"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shogo82148/go-sfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustBase(t *testing.T, opts ...BaseOption) *Base {
	t.Helper()
	b, err := NewBase(opts...)
	require.NoError(t, err, "NewBase")
	return b
}

// signatureInput returns the Signature-Input member under label in h.
func signatureInput(t *testing.T, h http.Header, label string) sfv.Item {
	t.Helper()
	dict, err := sfv.DecodeDictionary(h.Values("Signature-Input"))
	require.NoError(t, err, "parse Signature-Input")
	item := dict.Get(label)
	require.NotNil(t, item.Value, "Signature-Input has %q", label)
	return item
}

func paramKeys(params sfv.Parameters) []string {
	keys := make([]string, len(params))
	for i, p := range params {
		keys[i] = p.Key
	}
	return keys
}

func coveredIDs(t *testing.T, item sfv.Item) []string {
	t.Helper()
	list, ok := item.Value.(sfv.InnerList)
	require.True(t, ok, "Signature-Input member is an inner list")
	ids := make([]string, len(list))
	for i, c := range list {
		id, err := sfv.EncodeItem(c)
		require.NoError(t, err, "encode component identifier")
		ids[i] = id
	}
	return ids
}

// orderAs returns the resolved components in the order of ids.
func orderAs(t *testing.T, resolved []resolvedComponent, ids []string) []resolvedComponent {
	t.Helper()
	byID := make(map[string]resolvedComponent, len(resolved))
	for _, rc := range resolved {
		byID[rc.component.String()] = rc
	}
	require.Len(t, ids, len(byID), "covered components")
	ordered := make([]resolvedComponent, len(ids))
	for i, id := range ids {
		rc, ok := byID[id]
		require.True(t, ok, "%s is covered", id)
		ordered[i] = rc
	}
	return ordered
}

// rebuildBase returns the signature base of the signature under label on
// req, rebuilt as a verifier would: in the order given by its
// Signature-Input.
func rebuildBase(t *testing.T, b *Base, req *http.Request, label string) string {
	t.Helper()
	input := signatureInput(t, req.Header, label)
	resolved, err := b.resolve(requestMessage{req})
	require.NoError(t, err, "resolve")
	_, base, err := signatureBase(orderAs(t, resolved, coveredIDs(t, input)), input.Parameters)
	require.NoError(t, err, "build signature base")
	return string(base)
}

// signGET signs a GET request with base and returns the Signature-Input
// member of the new signature.
func signGET(t *testing.T, base *Base, opts ...SignOption) sfv.Item {
	t.Helper()
	req := newRequest(t, http.MethodGet, "https://example.com/path?q=1")
	label, err := base.SignRequest(rfcEd25519Key(t), req, opts...)
	require.NoError(t, err, "SignRequest")
	return signatureInput(t, req.Header, label)
}

func TestSignDefaults(t *testing.T) {
	created := time.Unix(1798761600, 0)
	input := signGET(t, mustBase(t, WithComponents(Method())), WithCreated(created))
	assert.ElementsMatch(t, []string{"alg", "created", "nonce"}, paramKeys(input.Parameters), "default parameters")
	assert.Equal(t, int64(1798761600), input.Parameters.Get("created"), "created")
	assert.Equal(t, "ed25519", input.Parameters.Get("alg"), "alg")
	nonce, ok := input.Parameters.Get("nonce").(string)
	require.True(t, ok, "nonce is a string")
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	require.NoError(t, err, "nonce is base64url")
	assert.Len(t, raw, 16, "nonce has 128 bits")
}

func TestSignCreatedDefaultsToNow(t *testing.T) {
	before := time.Now().Unix()
	input := signGET(t, mustBase(t, WithComponents(Method()), WithExpiry(time.Minute)))
	after := time.Now().Unix()
	created, ok := input.Parameters.Get("created").(int64)
	require.True(t, ok, "created is an integer")
	assert.GreaterOrEqual(t, created, before, "created")
	assert.LessOrEqual(t, created, after, "created")
	assert.Equal(t, created+60, input.Parameters.Get("expires"), "expires")
}

func TestSignParameters(t *testing.T) {
	b := mustBase(t, WithComponents(Method()),
		WithExtraParam("zz"), WithExtraParam("aa"),
		WithTag("t"), WithExpiry(time.Minute))
	input := signGET(t, b,
		WithCreated(time.Unix(1000, 0)), WithKeyID("k"),
		WithExtraParamValue("aa", "1"), WithExtraParamValue("zz", "2"))
	assert.ElementsMatch(t, []string{"alg", "created", "expires", "nonce", "keyid", "tag", "aa", "zz"},
		paramKeys(input.Parameters), "parameters")
	assert.Equal(t, int64(1060), input.Parameters.Get("expires"), "expires")
}

func TestSignRandomOrder(t *testing.T) {
	b := mustBase(t, WithComponents(Method(), Path(), Query(), Authority(), Scheme()),
		WithTag("t"), WithExpiry(time.Minute), WithExtraParam("x", "1"))
	key := rfcEd25519Key(t)
	components, params := map[string]bool{}, map[string]bool{}
	for range 50 {
		req := newRequest(t, http.MethodGet, "https://example.com/path?q=1")
		label, err := b.SignRequest(key, req, WithKeyID("k"))
		require.NoError(t, err, "SignRequest")
		input := signatureInput(t, req.Header, label)
		components[strings.Join(coveredIDs(t, input), " ")] = true
		params[strings.Join(paramKeys(input.Parameters), " ")] = true
		verifyRFC(t, key.Public(), crypto.Hash(0), rebuildBase(t, b, req, label), signatureFromHeader(t, req.Header, label))
	}
	assert.Greater(t, len(components), 1, "component order varies")
	assert.Greater(t, len(params), 1, "parameter order varies")
}

func TestBaseOptionsLastWins(t *testing.T) {
	for _, test := range []struct {
		name string
		opts []BaseOption
		want []string
	}{
		{"WithoutExpiry", []BaseOption{WithExpiry(time.Minute), WithoutExpiry()}, []string{"alg", "created", "nonce"}},
		{"WithExpiry", []BaseOption{WithoutExpiry(), WithExpiry(time.Minute)}, []string{"alg", "created", "expires", "nonce"}},
		{"WithoutNonce", []BaseOption{WithoutNonce()}, []string{"alg", "created"}},
		{"WithNonce", []BaseOption{WithoutNonce(), WithNonce()}, []string{"alg", "created", "nonce"}},
		{"WithoutAlg", []BaseOption{WithoutAlg()}, []string{"created", "nonce"}},
		{"WithAlg", []BaseOption{WithoutAlg(), WithAlg()}, []string{"alg", "created", "nonce"}},
		{"WithTag", []BaseOption{WithTag("a"), WithTag("b")}, []string{"alg", "created", "nonce", "tag"}},
		{"WithoutTag", []BaseOption{WithTag("a"), WithoutTag()}, []string{"alg", "created", "nonce"}},
		{"invalid expiry overridden", []BaseOption{WithExpiry(-time.Second), WithoutExpiry()}, []string{"alg", "created", "nonce"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := signGET(t, mustBase(t, append([]BaseOption{WithComponents(Method())}, test.opts...)...))
			assert.ElementsMatch(t, test.want, paramKeys(input.Parameters), "parameters")
			if slices.Contains(test.want, "tag") {
				assert.Equal(t, "b", input.Parameters.Get("tag"), "tag")
			}
		})
	}
}

func TestNewBaseInvalidOptions(t *testing.T) {
	for _, test := range []struct {
		name string
		opts []BaseOption
	}{
		{"zero expiry", []BaseOption{WithExpiry(0)}},
		{"negative expiry", []BaseOption{WithExpiry(-time.Minute)}},
		{"invalid tag", []BaseOption{WithTag("café")}},
		{"tag with control char", []BaseOption{WithTag("a\nb")}},
		{"reserved extra", []BaseOption{WithExtraParam("keyid")}},
		{"invalid extra", []BaseOption{WithExtraParam("Bad")}},
		{"empty extra", []BaseOption{WithExtraParam("")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewBase(append([]BaseOption{WithComponents(Method())}, test.opts...)...)
			require.ErrorIs(t, err, ErrInvalidParameter, "NewBase")
		})
	}
}

func TestNewBaseReportsAllErrors(t *testing.T) {
	_, err := NewBase(WithComponents(Field("bad name"), Method()),
		WithExpiry(0), WithExtraParam("nonce"))
	require.ErrorIs(t, err, ErrInvalidComponent, "NewBase")
	require.ErrorIs(t, err, ErrInvalidParameter, "NewBase")
}

func TestSignExtraParams(t *testing.T) {
	b := mustBase(t, WithComponents(Method()),
		WithExtraParam("s"), WithExtraParam("i"), WithExtraParam("b"), WithExtraParam("y"))
	input := signGET(t, b,
		WithExtraParamValue("s", "str"),
		WithExtraParamValue("i", int64(-42)),
		WithExtraParamValue("b", false),
		WithExtraParamValue("y", []byte{1, 2, 3}),
		WithExtraParamValue("s", "last wins"))
	assert.ElementsMatch(t, []string{"alg", "created", "nonce", "b", "i", "s", "y"},
		paramKeys(input.Parameters), "parameters")
	assert.Equal(t, "last wins", input.Parameters.Get("s"), "string value")
	assert.Equal(t, int64(-42), input.Parameters.Get("i"), "integer value")
	assert.Equal(t, false, input.Parameters.Get("b"), "boolean value")
	assert.Equal(t, []byte{1, 2, 3}, input.Parameters.Get("y"), "byte sequence value")

	for _, test := range []struct {
		name string
		opts []SignOption
		want error
	}{
		{"missing", nil, ErrMissingParameter},
		{"undeclared", []SignOption{WithExtraParamValue("x", "1"), WithExtraParamValue("other", "2")}, ErrInvalidParameter},
		{"unsupported type", []SignOption{WithExtraParamValue("x", 1)}, ErrInvalidParameter},
		{"invalid string", []SignOption{WithExtraParamValue("x", "café")}, ErrInvalidParameter},
		{"integer out of range", []SignOption{WithExtraParamValue("x", int64(1e15))}, ErrInvalidParameter},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := newRequest(t, http.MethodGet, "https://example.com/")
			_, err := mustBase(t, WithComponents(Method()), WithExtraParam("x")).
				SignRequest(rfcEd25519Key(t), req, test.opts...)
			require.ErrorIs(t, err, test.want, "SignRequest")
			assert.Empty(t, req.Header, "request is unchanged on error")
		})
	}
}

func TestSignExtraParamDefaults(t *testing.T) {
	b := mustBase(t, WithComponents(Method()), WithExtraParam("x", "default"))
	input := signGET(t, b)
	assert.Equal(t, "default", input.Parameters.Get("x"), "default value")

	input = signGET(t, b, WithExtraParamValue("x", "override"))
	assert.Equal(t, "override", input.Parameters.Get("x"), "WithExtraParamValue overrides the default")

	// Re-declaring a parameter replaces the earlier declaration.
	input = signGET(t, mustBase(t, WithComponents(Method()),
		WithExtraParam("x", "first"), WithExtraParam("x", int64(2))))
	assert.Equal(t, int64(2), input.Parameters.Get("x"), "last declaration wins")

	req := newRequest(t, http.MethodGet, "https://example.com/")
	_, err := mustBase(t, WithComponents(Method()), WithExtraParam("x", "first"), WithExtraParam("x")).
		SignRequest(rfcEd25519Key(t), req)
	require.ErrorIs(t, err, ErrMissingParameter, "re-declaring without a default drops the default")

	assert.Panics(t, func() { WithExtraParam("x", "a", "b") }, "more than one default")
}

func TestSignNonce(t *testing.T) {
	input := signGET(t, mustBase(t, WithComponents(Method())), WithNonceValue("my-nonce"))
	assert.Equal(t, "my-nonce", input.Parameters.Get("nonce"), "nonce")

	req := newRequest(t, http.MethodGet, "https://example.com/")
	_, err := mustBase(t, WithComponents(Method()), WithoutNonce()).
		SignRequest(rfcEd25519Key(t), req, WithNonceValue("my-nonce"))
	require.ErrorIs(t, err, ErrNonceNotEnabled, "WithNonceValue with WithoutNonce")

	_, err = mustBase(t, WithComponents(Method())).
		SignRequest(rfcEd25519Key(t), req, WithNonceValue("café"))
	require.ErrorIs(t, err, ErrInvalidParameter, "invalid nonce")

	_, err = mustBase(t, WithComponents(Method())).
		SignRequest(rfcEd25519Key(t), req, WithKeyID("café"))
	require.ErrorIs(t, err, ErrInvalidParameter, "invalid keyid")
	assert.Empty(t, req.Header, "request is unchanged on error")
}

func TestSignLabels(t *testing.T) {
	b := mustBase(t, WithComponents(Method()))
	key := rfcEd25519Key(t)
	req := newRequest(t, http.MethodGet, "https://example.com/")

	sign := func(opts ...SignOption) string {
		t.Helper()
		label, err := b.SignRequest(key, req, opts...)
		require.NoError(t, err, "SignRequest")
		signatureInput(t, req.Header, label)
		signatureFromHeader(t, req.Header, label)
		return label
	}
	assert.Equal(t, "s1", sign(), "first label")
	assert.Equal(t, "custom", sign(WithSigLabel("custom")), "custom label")
	assert.Equal(t, "s3", sign(), "label after a custom one")
	assert.Equal(t, "s5", sign(WithSigLabel("s5")), "hand-picked s<N> label")
	assert.Equal(t, "s6", sign(), "label skips a hand-picked one")
	assert.Equal(t, "s7", sign(), "next label")
	assert.Len(t, req.Header.Values("Signature-Input"), 6, "one Signature-Input line per signature")
	assert.Len(t, req.Header.Values("Signature"), 6, "one Signature line per signature")

	before := req.Header.Clone()
	for _, test := range []struct {
		label string
		want  error
	}{
		{"custom", ErrLabelExists},
		{"s1", ErrLabelExists},
		{"", ErrInvalidLabel},
		{"Upper", ErrInvalidLabel},
		{"1abc", ErrInvalidLabel},
	} {
		_, err := b.SignRequest(key, req, WithSigLabel(test.label))
		require.ErrorIs(t, err, test.want, "WithSigLabel(%q)", test.label)
	}
	assert.Equal(t, before, req.Header, "request is unchanged on error")

	// A label only present in Signature is also taken.
	req = newRequest(t, http.MethodGet, "https://example.com/")
	req.Header.Set("Signature", "s1=:AAAA:")
	_, err := b.SignRequest(key, req, WithSigLabel("s1"))
	require.ErrorIs(t, err, ErrLabelExists, "label in Signature only")
	assert.Equal(t, "s2", sign(), "default label skips a label in Signature")
}

func TestSignMalformedExisting(t *testing.T) {
	b := mustBase(t, WithComponents(Method()))
	for _, field := range []string{"Signature-Input", "Signature"} {
		req := newRequest(t, http.MethodGet, "https://example.com/")
		req.Header.Set(field, "not a dictionary!")
		_, err := b.SignRequest(rfcEd25519Key(t), req)
		require.ErrorIs(t, err, ErrMalformedSignature, "malformed %s", field)
		assert.Len(t, req.Header, 1, "request is unchanged on error")
	}
}

func TestSignOptionalComponents(t *testing.T) {
	b := mustBase(t,
		WithComponents(Method()),
		WithOptionalComponents(Field("content-type")),
		WithComponents(Path()),
		WithoutNonce(), WithoutAlg())

	input := signGET(t, b)
	assert.ElementsMatch(t, []string{`"@method"`, `"@path"`}, coveredIDs(t, input), "absent field is not covered")

	req := newRequest(t, http.MethodGet, "https://example.com/path?q=1")
	req.Header.Set("Content-Type", "text/plain")
	label, err := b.SignRequest(rfcEd25519Key(t), req, WithCreated(rfcCreated))
	require.NoError(t, err, "SignRequest")
	input = signatureInput(t, req.Header, label)
	assert.ElementsMatch(t, []string{`"@method"`, `"content-type"`, `"@path"`}, coveredIDs(t, input), "present field is covered")

	// Check that the base really omits the absent field.
	req = newRequest(t, http.MethodGet, "https://example.com/path?q=1")
	label, err = b.SignRequest(rfcEd25519Key(t), req, WithCreated(rfcCreated))
	require.NoError(t, err, "SignRequest")
	base := rebuildBase(t, b, req, label)
	assert.NotContains(t, base, "content-type", "signature base")
	verifyRFC(t, rfcEd25519Key(t).Public(), crypto.Hash(0), base, signatureFromHeader(t, req.Header, label))
}

func TestSignRejectsComponents(t *testing.T) {
	for _, test := range []struct {
		component Component
		want      error
	}{
		{Status(), ErrResponseOnlyComponent},
		{Field("content-type").FromRequest(), ErrResponseOnlyComponent},
		{Field("content-type"), ErrMissingComponent},
		{Field("host"), ErrInvalidComponent},
	} {
		req := newRequest(t, http.MethodGet, "https://example.com/")
		_, err := mustBase(t, WithComponents(test.component)).SignRequest(rfcEd25519Key(t), req)
		require.ErrorIs(t, err, test.want, "sign covering %s", test.component)
		var cerr *ComponentError
		require.ErrorAs(t, err, &cerr, "sign covering %s", test.component)
		assert.Equal(t, test.component, cerr.Component, "ComponentError.Component")
		assert.Empty(t, req.Header, "request is unchanged on error")
	}
}

type opaqueKey struct{}

type testSigner struct {
	pub crypto.PublicKey
}

func (s testSigner) Public() crypto.PublicKey { return s.pub }

func (testSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("must not be called")
}

func TestSignUnsupported(t *testing.T) {
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err, "generate P-521 key")
	p256 := rfcECCP256Key(t)
	rsaKey := rfcRSAKey(t)

	for _, test := range []struct {
		name   string
		signer crypto.Signer
		opts   crypto.SignerOpts
		want   error
	}{
		{"opaque key", testSigner{opaqueKey{}}, nil, ErrUnsupportedKey},
		{"P-521", p521, nil, ErrUnsupportedKey},
		{"ed25519 with hash", rfcEd25519Key(t), crypto.SHA512, ErrUnsupportedSignerOpts},
		{"ed25519ph", rfcEd25519Key(t), &ed25519.Options{Hash: crypto.SHA512}, ErrUnsupportedSignerOpts},
		{"ed25519ctx", rfcEd25519Key(t), &ed25519.Options{Context: "x"}, ErrUnsupportedSignerOpts},
		{"P-256 with SHA-384", p256, crypto.SHA384, ErrUnsupportedSignerOpts},
		{"RSA PSS auto salt", rsaKey, &rsa.PSSOptions{Hash: crypto.SHA512, SaltLength: rsa.PSSSaltLengthAuto}, ErrUnsupportedSignerOpts},
		{"RSA PSS SHA-256", rsaKey, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash}, ErrUnsupportedSignerOpts},
		{"RSA v1.5 SHA-512", rsaKey, crypto.SHA512, ErrUnsupportedSignerOpts},
	} {
		t.Run(test.name, func(t *testing.T) {
			// The algorithm is checked even when alg is not emitted.
			b := mustBase(t, WithComponents(Method()), WithoutAlg())
			req := newRequest(t, http.MethodGet, "https://example.com/")
			var opts []SignOption
			if test.opts != nil {
				opts = append(opts, WithSignerOpts(test.opts))
			}
			_, err := b.SignRequest(test.signer, req, opts...)
			require.ErrorIs(t, err, test.want, "SignRequest")
			assert.Empty(t, req.Header, "request is unchanged on error")
		})
	}
}

// The WIMSE workload-to-workload profile (draft-ietf-wimse-http-signature-08
// section 3).
func TestWIMSEProfile(t *testing.T) {
	witBase := mustBase(t,
		WithComponents(
			Method(),
			Path(),
			Query(),
			Field("workload-identity-token"),
		),
		WithOptionalComponents(
			Field("content-type"),
			Field("content-digest"),
			Field("authorization"),
			Field("txn-token"),
		),
		WithExpiry(time.Minute),
		WithoutAlg(),
		WithTag("wimse-workload-to-workload"),
		WithExtraParam("wimse-aud"),
	)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate key")

	req := newRequest(t, http.MethodGet, "https://repo.example.com/metadata/1.root.json?x=y")
	req.Header.Set("Workload-Identity-Token", "wit")
	label, err := witBase.SignRequest(key, req,
		WithSigLabel("wimse"), WithExtraParamValue("wimse-aud", "quarry"), WithCreated(rfcCreated))
	require.NoError(t, err, "SignRequest")
	assert.Equal(t, "wimse", label, "label")

	input := signatureInput(t, req.Header, label)
	assert.ElementsMatch(t, []string{`"@method"`, `"@path"`, `"@query"`, `"workload-identity-token"`},
		coveredIDs(t, input), "covered components")
	assert.ElementsMatch(t, []string{"created", "expires", "nonce", "tag", "wimse-aud"},
		paramKeys(input.Parameters), "parameters")
	assert.Equal(t, "wimse-workload-to-workload", input.Parameters.Get("tag"), "tag")
	assert.Equal(t, "quarry", input.Parameters.Get("wimse-aud"), "wimse-aud")
	assert.Equal(t, int64(1618884473+60), input.Parameters.Get("expires"), "expires")
}

func TestSignConcurrent(t *testing.T) {
	b := mustBase(t, WithComponents(Method(), TargetURI(), Field("x-n")), WithExpiry(time.Minute))
	key := rfcEd25519Key(t)

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			for j := range 20 {
				req := newRequest(t, http.MethodGet, "https://example.com/")
				req.Header.Set("X-N", strings.Repeat("x", i+j))
				if _, err := b.SignRequest(key, req); err != nil {
					t.Errorf("SignRequest: %v", err)
				}
			}
		})
	}
	wg.Wait()
}
