// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// Package identityagent signs HTTP requests as this machine, for servers
// such as the Amutable quarry-worker that serve a repository only to the
// machine it belongs to.
//
// The client holds its own P-256 key. amutablectl's com.amutable.IdentityAgent
// varlink service, which holds the device key, attests quarry-client by its
// systemd unit and returns the machine's WIMSE workload identity token (WIT)
// bound to that key. The client then signs each request itself, per the WIMSE
// workload-to-workload profile of RFC 9421:
// <https://datatracker.ietf.org/doc/draft-ietf-wimse-http-signature/>.
package identityagent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.amutable.dev/quarry/internal/varlink"
)

const vlInterface = "com.amutable.IdentityAgent"

// DefaultSocketURI is the varlink URI of amutablectl's identity agent.
const DefaultSocketURI = "unix:/run/amutable/" + vlInterface

// refreshMargin is how long before expiry a WIT is replaced, so a request
// signed just before expiry still arrives with a valid one.
const refreshMargin = 5 * time.Minute

const (
	witHeader      = "workload-identity-token"
	signatureLabel = "wimse"
	signatureTag   = "wimse-workload-to-workload"
)

type witParams struct {
	Audience  string `json:"audience"`
	PublicKey string `json:"public_key"`
}

type witReply struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"`
}

// Transport is an [http.RoundTripper] that signs every request to Host as this
// machine, with a WIT for Audience. Requests to other hosts go out unsigned,
// so the WIT never reaches a server it was not minted for.
//
// Only bodiless requests are signed correctly: no body digest is covered.
type Transport struct {
	// Audience is the WIT audience the server accepts.
	Audience string
	// Host is the URL host (with port, if any) whose requests are signed.
	Host string
	// SocketURI is the agent's varlink URI; empty means [DefaultSocketURI].
	SocketURI string

	mu     sync.Mutex
	key    *ecdsa.PrivateKey
	wit    string
	expiry time.Time
}

// RoundTrip implements [http.RoundTripper]. It fails the request if no WIT can
// be obtained, rather than sending it unsigned.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != t.Host {
		return http.DefaultTransport.RoundTrip(req)
	}

	key, wit, err := t.credential(req)
	if err != nil {
		return nil, fmt.Errorf("get WIT for %s from the identity agent: %w", req.URL.Host, err)
	}
	input, sig, err := sign(key, wit, req.Method, req.URL.String(), time.Now())
	if err != nil {
		return nil, fmt.Errorf("sign request to %s: %w", req.URL.Host, err)
	}

	// A RoundTripper must not modify the caller's request.
	req = req.Clone(req.Context())
	req.Header.Set("Workload-Identity-Token", wit)
	req.Header.Set("Signature-Input", signatureLabel+"="+input)
	req.Header.Set("Signature", signatureLabel+"=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return http.DefaultTransport.RoundTrip(req)
}

var (
	clientsMu sync.Mutex
	clients   = map[[3]string]*http.Client{}
)

// Client returns the process-wide client that signs requests to host with a
// WIT for audience from the agent at socketURI (empty means
// [DefaultSocketURI]), creating it on first use. Callers that rebuild their
// configuration often, such as "quarry-client http" on every request, then
// keep one signing key and reuse its WIT until it nears expiry.
func Client(audience, host, socketURI string) *http.Client {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	k := [3]string{audience, host, socketURI}
	c, ok := clients[k]
	if !ok {
		c = &http.Client{Transport: &Transport{Audience: audience, Host: host, SocketURI: socketURI}}
		clients[k] = c
	}
	return c
}

// credential returns the signing key and a WIT bound to it, asking the agent
// for a new WIT when the cached one is close to expiry. The key lives as long
// as the Transport and never leaves the process.
func (t *Transport) credential(req *http.Request) (*ecdsa.PrivateKey, string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	if t.wit != "" && now.Add(refreshMargin).Before(t.expiry) {
		return t.key, t.wit, nil
	}
	if t.key == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, "", fmt.Errorf("generate signing key: %w", err)
		}
		t.key = key
	}
	pub, err := t.key.PublicKey.Bytes()
	if err != nil {
		return nil, "", fmt.Errorf("encode signing key: %w", err)
	}

	uri := t.SocketURI
	if uri == "" {
		uri = DefaultSocketURI
	}
	reply, err := varlink.Call[witReply](req.Context(), uri, vlInterface+".GetWorkloadIdentityToken", witParams{
		Audience:  t.Audience,
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
	})
	if err != nil {
		return nil, "", err
	}
	if reply == nil || reply.Token == "" {
		return nil, "", fmt.Errorf("empty reply")
	}
	t.wit = reply.Token
	t.expiry = now.Add(time.Duration(reply.ExpiresIn) * time.Second)
	return t.key, t.wit, nil
}

// sign returns the Signature-Input member and the raw ES256 signature (r||s)
// over the RFC 9421 signature base of a bodiless request: the WIT header,
// @method and @target-uri, in that order. @target-uri rather than
// @request-target, so the signature does not verify on another host or scheme.
func sign(key *ecdsa.PrivateKey, wit, method, targetURI string, now time.Time) (string, []byte, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", nil, fmt.Errorf("generate nonce: %w", err)
	}
	input := fmt.Sprintf(`("%s" "@method" "@target-uri");created=%d;nonce="%s";tag="%s"`,
		witHeader, now.Unix(), hex.EncodeToString(nonce[:]), signatureTag)
	base := strings.Join([]string{
		fmt.Sprintf(`"%s": %s`, witHeader, wit),
		`"@method": ` + method,
		`"@target-uri": ` + targetURI,
		`"@signature-params": ` + input,
	}, "\n")

	digest := sha256.Sum256([]byte(base))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", nil, fmt.Errorf("ecdsa sign: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input, sig, nil
}
