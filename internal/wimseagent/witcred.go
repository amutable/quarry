// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package wimseagent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go4org/hashtriemap"

	"go.amutable.dev/quarry/internal/varlink"
)

// credCache is a thread-safe cache of all credentials keyed by the ID so that
// clients can independently refresh the same underlying WIT credential.
var credCache = new(hashtriemap.HashTrieMap[ID, *WitCred])

// ID represents a unique identity that is backed by a short-lived WIT provided
// by a com.amutable.IdentityAgent-compatible identity provider.
type ID struct {
	// WitAudience is the audience that the WIT generated for this identity is
	// signed for.
	// TODO: Should we support requesting multiple audiences? It seems more
	// prudent to treat each audience as a unique identity.
	WitAudience string

	// Provider is the socket URI which is used to sign the WITs generated for
	// this identity. Because it is possible for different providers to provide
	// WITs with the same audience, this is considered part of the credential's
	// unique "identity". Empty means [DefaultSocketURI].
	Provider string
}

// WitCred is a longer-lived credential that can be used to mint new WITs as
// they expire. The [crypto.Signer] used to sign requests with this credential
// is stored within [WitCred], so use [WitCred.Signer] to access the signing
// handle.
type WitCred struct {
	// ID is the credential identity used to refresh this wit.
	id ID
	// key and pubJwk are static once a credential is created, we do not do key
	// rotation for WIT keys since we expect the service to not be particularly
	// long-lived.
	// TODO: Should we rotate these keys on each credential refresh...?
	key    crypto.Signer
	pubJwk jose.JSONWebKey
	// witMu protects the wit and expiry.
	witMu  sync.RWMutex
	wit    string
	expiry time.Time
}

// ID returns the [ID] for this [WitCred].
func (w *WitCred) ID() ID { return w.id }

// Signer returns the [crypto.Signer] for the key associated with the WIT.
func (w *WitCred) Signer() crypto.Signer { return w.key }

// SignerOpts returns the signing options needed for using [crypto.SignMessage]
// with [WitCred.Signer] and this WIT.
func (w *WitCred) SignerOpts() (crypto.SignerOpts, error) {
	// TODO: We should parse out the algorithm from the WIT's jwk.cfg.alg
	// rather than just using the one we requested, as in principle we might've
	// been given a different signing algorithm in the WIT.
	return jwkSignerOpts(w.pubJwk)
}

// NewCred tries to creates a new [WitCred] credential with the [crypto.Signer]
// acting as the private key for the credential. Note that since [WitCred]s are
// cached, if there is an existing credential with the same [ID] then the
// [crypto.Signer] is ignored and the existing [WitCred] is returned. If the
// provided [crypto.Signer] is nil, a new in-memory key will be generated.
func NewCred(id ID, key crypto.Signer) (*WitCred, error) {
	if id.Provider == "" {
		id.Provider = DefaultSocketURI
	}
	// Fast path -- if the cache is already filled then skip generating a key.
	if wit, ok := credCache.Load(id); ok {
		return wit, nil
	}
	// Generate a new key if we were not told to use a particular key.
	if key == nil {
		var err error
		// TODO: Possibly make this less hardcoded? (And switch to Ed25519! :P)
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate signing key: %w", err)
		}
	}
	pubJwk, err := toJwkPublic(key.Public())
	if err != nil {
		return nil, fmt.Errorf("generate public jwk for signing key: %w", err)
	}
	// Try to insert a candidate "blank" WIT credential into the cache, but
	// re-use an existing one if it was present.
	wit, _ := credCache.LoadOrStore(id, &WitCred{
		id:     id,
		key:    key,
		pubJwk: pubJwk,
	})
	return wit, nil
}

// refreshMargin is how long before expiry a WIT is replaced, so a request
// signed just before expiry still arrives with a valid one.
const refreshMargin = 5 * time.Minute

const vlInterface = "com.amutable.IdentityAgent"

// DefaultSocketURI is the varlink URI of amutablectl's identity agent.
const DefaultSocketURI = "unix:/run/amutable/" + vlInterface

type witParams struct {
	Audience  string          `json:"aud"`
	PublicKey jose.JSONWebKey `json:"jwk_pub"`
}

type witReply struct {
	Token     string `json:"wit"`
	ExpiresIn int64  `json:"expires_in"`
}

// Credential returns the WIT for this [WitCred], potentially refreshing it if
// the WIT has expired since its last usage. The WIT should be used immediately
// after this operation, as the expiry may be quite short.
//
// TODO: Maybe we should return the expiry too...?
func (w *WitCred) Credential(ctx context.Context) (string, error) {
	// checkLockedWit checks that the wit is valid and has not expired. If the
	// wit has expired, valid will be false and the caller must refresh the
	// wit. checkLockedWit must be called with at least w.witMu.RLock held.
	checkLockedWit := func(w *WitCred) (wit string, valid bool) {
		return w.wit, w.wit != "" && time.Now().Add(refreshMargin).Before(w.expiry)
	}

	w.witMu.RLock()
	wit, ok := checkLockedWit(w)
	w.witMu.RUnlock()
	if ok {
		return wit, nil
	}

	// We need to refresh the wit.
	w.witMu.Lock()
	defer w.witMu.Unlock()
	// Because we cannot upgrade from a read to a write lock atomically it is
	// possible multiple racing goroutines hit the same path, so make sure to
	// double-check the wit is still expired once we get exclusive access.
	if wit, ok := checkLockedWit(w); ok {
		return wit, nil
	}
	now := time.Now()

	uri := w.ID().Provider
	reply, err := varlink.Call[witReply](ctx, uri, vlInterface+".GetWorkloadIdentityToken", witParams{
		Audience:  w.ID().WitAudience,
		PublicKey: w.pubJwk,
	})
	if err != nil {
		return "", err
	}

	if reply == nil || reply.Token == "" {
		return "", fmt.Errorf("bad provider %s: empty reply to GetWorkloadIdentityToken request", uri)
	}

	w.wit = reply.Token
	w.expiry = now.Add(time.Duration(reply.ExpiresIn) * time.Second)
	return w.wit, nil
}
