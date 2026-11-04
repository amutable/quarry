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
	"encoding/json"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"snai.pe/go-varlink"
)

// agentCall is one GetWorkloadIdentityToken call seen by the fake agent.
type agentCall struct {
	Audience string
	JWK      jose.JSONWebKey
	// Members are the sorted member names of the JWK as sent.
	Members []string
}

// expiringIn returns a fake agent reply that names the call number and
// expires after the given number of seconds.
func expiringIn(seconds int64) func(n int) witReply {
	return func(n int) witReply {
		return witReply{Token: "wit-" + strconv.Itoa(n), ExpiresIn: seconds}
	}
}

// startFakeAgent serves GetWorkloadIdentityToken with reply, recording each
// call. Like the real agent, it rejects a JWK that is not a valid public key.
func startFakeAgent(t *testing.T, reply func(n int) witReply) (string, func() []agentCall) {
	t.Helper()
	uri := "unix:" + filepath.Join(t.TempDir(), vlInterface) //nolint:forbidigo // test code
	listener, err := varlink.Listen(uri)
	require.NoError(t, err, "listen on fake agent socket")
	t.Cleanup(func() { _ = listener.Close() })

	var (
		mu    sync.Mutex
		calls []agentCall
		mux   varlink.ServeMux
	)
	mux.HandleFunc(vlInterface+".GetWorkloadIdentityToken", func(w varlink.ReplyWriter, c *varlink.Call) {
		var p witParams
		if err := c.Unmarshal(&p); err != nil {
			_ = w.WriteError(err)
			return
		}
		var raw struct {
			JWK map[string]json.RawMessage `json:"jwk_pub"`
		}
		if !p.PublicKey.Valid() || !p.PublicKey.IsPublic() || json.Unmarshal(c.Parameters, &raw) != nil {
			_ = w.WriteError(varlink.NewError("org.varlink.service.InvalidParameter", "parameter", "jwk_pub"))
			return
		}
		mu.Lock()
		calls = append(calls, agentCall{
			Audience: p.Audience,
			JWK:      p.PublicKey,
			Members:  slices.Sorted(maps.Keys(raw.JWK)),
		})
		n := len(calls)
		mu.Unlock()
		_ = w.WriteReply(reply(n))
	})
	srv := &varlink.Server{Handler: &mux}
	go func() { _ = srv.Serve(listener) }()
	return uri, func() []agentCall {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(calls)
	}
}

// newCred returns a credential with a fresh P-256 key for the agent at
// provider. Each test uses its own provider, so the shared cache never hands a
// test another test's credential.
func newCred(t *testing.T, witAudience, provider string) *WitCred {
	t.Helper()
	cred, err := NewCred(ID{WitAudience: witAudience, Provider: provider}, nil)
	require.NoError(t, err, "NewCred")
	return cred
}

func thumbprint(t *testing.T, jwk jose.JSONWebKey) []byte {
	t.Helper()
	tp, err := jwk.Thumbprint(crypto.SHA256)
	require.NoError(t, err, "JWK thumbprint")
	return tp
}

func TestNewCredSharedPerID(t *testing.T) {
	provider := "unix:" + filepath.Join(t.TempDir(), "agent") //nolint:forbidigo // test code
	cred := newCred(t, "aud", provider)
	assert.Same(t, cred, newCred(t, "aud", provider), "same identity")
	assert.NotSame(t, cred, newCred(t, "other", provider), "other WIT audience")
	assert.NotSame(t, cred, newCred(t, "aud", provider+"-other"), "other provider")
}

func TestNewCredDefaultProvider(t *testing.T) {
	audience := "urn:example:" + t.Name()
	cred := newCred(t, audience, "")
	assert.Equal(t, DefaultSocketURI, cred.ID().Provider, "empty provider is the default agent")
	assert.Same(t, cred, newCred(t, audience, DefaultSocketURI), "same identity as the explicit default")
}

func TestNewCredCachedIgnoresKey(t *testing.T) {
	id := ID{WitAudience: "aud", Provider: "unix:" + filepath.Join(t.TempDir(), "agent")} //nolint:forbidigo // test code
	cred, err := NewCred(id, nil)
	require.NoError(t, err, "NewCred")

	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "generate Ed25519 key")
	again, err := NewCred(id, ed)
	require.NoError(t, err, "NewCred with a key for a cached identity")
	assert.Same(t, cred, again, "the cached credential is returned")
	_, isECDSA := again.Signer().Public().(*ecdsa.PublicKey)
	assert.True(t, isECDSA, "the cached credential keeps its key")
}

func TestNewCredUnsupportedKey(t *testing.T) {
	agent, calls := startFakeAgent(t, expiringIn(3600))
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err, "generate P-521 key")

	_, err = NewCred(ID{WitAudience: "aud", Provider: agent}, p521)
	require.Error(t, err, "NewCred with a key httpsig cannot sign with")
	assert.Empty(t, calls(), "no WIT is minted")
}

func TestCredentialCachesUntilNearExpiry(t *testing.T) {
	agent, calls := startFakeAgent(t, expiringIn(3600))
	cred := newCred(t, "urn:amutable:wit", agent)

	for range 2 {
		wit, err := cred.Credential(t.Context())
		require.NoError(t, err, "Credential")
		assert.Equal(t, "wit-1", wit, "WIT")
	}

	require.Len(t, calls(), 1, "the WIT is reused until it nears expiry")
	call := calls()[0]
	assert.Equal(t, "urn:amutable:wit", call.Audience, "WIT audience")
	assert.Equal(t, []string{"alg", "crv", "kty", "x", "y"}, call.Members, "only public members are sent")
	assert.Equal(t, string(jose.ES256), call.JWK.Algorithm, "alg of the default key")
	pub, _ := cred.Signer().Public().(*ecdsa.PublicKey)
	assert.True(t, pub.Equal(call.JWK.Key), "the agent binds the signing key")
}

func TestCredentialRefreshesNearExpiry(t *testing.T) {
	// Already inside refreshMargin, so every call asks for a new WIT.
	agent, calls := startFakeAgent(t, expiringIn(int64(refreshMargin/time.Second)-1))
	cred := newCred(t, "aud", agent)

	for i := range 2 {
		wit, err := cred.Credential(t.Context())
		require.NoError(t, err, "Credential")
		assert.Equal(t, "wit-"+strconv.Itoa(i+1), wit, "a new WIT each time")
	}
	require.Len(t, calls(), 2, "agent calls")
	assert.Equal(t, thumbprint(t, calls()[0].JWK), thumbprint(t, calls()[1].JWK), "the key outlives the WIT")
}

func TestCredentialConcurrentRefresh(t *testing.T) {
	agent, calls := startFakeAgent(t, expiringIn(3600))
	cred := newCred(t, "aud", agent)

	var (
		wg   sync.WaitGroup
		wits [16]string
		errs [16]error
	)
	for i := range wits {
		wg.Go(func() { wits[i], errs[i] = cred.Credential(t.Context()) })
	}
	wg.Wait()
	for i := range wits {
		require.NoError(t, errs[i], "Credential")
		assert.Equal(t, "wit-1", wits[i], "WIT")
	}
	assert.Len(t, calls(), 1, "racing callers share one refresh")
}

func TestCredentialErrors(t *testing.T) {
	t.Run("Unreachable", func(t *testing.T) {
		cred := newCred(t, "aud", "unix:"+filepath.Join(t.TempDir(), "missing")) //nolint:forbidigo // test code
		_, err := cred.Credential(t.Context())
		require.Error(t, err, "Credential with no agent")
	})
	t.Run("EmptyReply", func(t *testing.T) {
		agent, _ := startFakeAgent(t, func(int) witReply { return witReply{ExpiresIn: 3600} })
		cred := newCred(t, "aud", agent)
		_, err := cred.Credential(t.Context())
		require.ErrorContains(t, err, "empty reply", "Credential with an empty WIT")
	})
}

func TestNewCredKeyTypes(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err, "generate P-384 key")
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "generate Ed25519 key")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "generate RSA key")

	for _, test := range []struct {
		name    string
		key     crypto.Signer
		wantAlg jose.SignatureAlgorithm
	}{
		{"Default", nil, jose.ES256},
		{"P384", p384, jose.ES384},
		{"Ed25519", ed, "Ed25519"},
		{"RSA", rsaKey, jose.PS512},
	} {
		t.Run(test.name, func(t *testing.T) {
			agent, calls := startFakeAgent(t, expiringIn(3600))
			cred, err := NewCred(ID{WitAudience: "aud", Provider: agent}, test.key)
			require.NoError(t, err, "NewCred")
			if test.key != nil {
				pub, _ := test.key.Public().(interface{ Equal(crypto.PublicKey) bool })
				assert.True(t, pub.Equal(cred.Signer().Public()), "the given key is used")
			}

			got := signedRequest(t, &Transport{WitCred: cred, WimseAudience: "wimse"})
			require.Len(t, calls(), 1, "agent calls")
			assert.Equal(t, string(test.wantAlg), calls()[0].JWK.Algorithm, "JWK alg")
			verify(t, got, "wimse", calls()[0].JWK, witComponents)
		})
	}
}
