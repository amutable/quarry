// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

//go:build fixtures

// acp-sample-gen regenerates the control plane's
// deploy/cloudflare/quarry-worker/test/fixtures/go-signed-read.json, which
// pins the Worker's verifier to what Transport puts on the wire:
//
//	go run -tags fixtures ./internal/fixtures/acp-sample-gen \
//	  <control-plane>/deploy/cloudflare/quarry-worker/test/fixtures/go-signed-read.json
//
// Transport gets its WIT from a fake identity agent, which mints one with a
// throwaway tenant key and binds the key Transport asked for.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"snai.pe/go-varlink"

	"go.amutable.dev/quarry/internal/wimseagent"
)

const (
	broker   = "https://wit-broker.test"
	tenant   = "acme"
	stamp    = "test.example"
	machine  = "0123456789abcdef0123456789abcdef"
	audience = "urn:amutable:quarry-worker"
	kid      = "tenant-key"
	// publicURL is the Worker tests' PUBLIC_URL, so the request's default
	// wimse-aud (its target URI) is one the Worker accepts.
	publicURL = "https://customerdata.test"
)

// captureTransport records the headers of the one request sent through it,
// so the signed request never has to reach a server at publicURL.
type captureTransport struct {
	header http.Header
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.header = req.Header.Clone()
	return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Request: req}, nil
}

var b64 = base64.RawURLEncoding.EncodeToString

func es256JWT(key *ecdsa.PrivateKey, header, claims any) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64(h) + "." + b64(c)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + b64(sig), nil
}

// p256JWK returns the JWK to bind into the WIT for jwk. Like the real agent,
// it only accepts P-256 public keys with "alg" ES256, which WIMSE requires.
func p256JWK(jwk jose.JSONWebKey) (jose.JSONWebKey, error) {
	pub, ok := jwk.Key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || !jwk.Valid() {
		return jose.JSONWebKey{}, fmt.Errorf("not a P-256 public key: %T", jwk.Key)
	}
	if jwk.Algorithm != string(jose.ES256) {
		return jose.JSONWebKey{}, fmt.Errorf("alg %q does not match a P-256 key", jwk.Algorithm)
	}
	return jose.JSONWebKey{Key: pub, Algorithm: string(jose.ES256)}, nil
}

// startAgent serves GetWorkloadIdentityToken from a socket in dir, replying
// with a WIT signed by tenantKey and bound to the requested key.
func startAgent(dir string, tenantKey *ecdsa.PrivateKey, now time.Time) (string, error) {
	uri := "unix:" + dir + "/agent"
	listener, err := varlink.Listen(uri)
	if err != nil {
		return "", fmt.Errorf("listen on fake agent socket: %w", err)
	}
	var mux varlink.ServeMux
	mux.HandleFunc("com.amutable.IdentityAgent.GetWorkloadIdentityToken", func(w varlink.ReplyWriter, c *varlink.Call) {
		var p struct {
			Audience  string          `json:"aud"`
			PublicKey jose.JSONWebKey `json:"jwk_pub"`
		}
		if err := c.Unmarshal(&p); err != nil {
			_ = w.WriteError(err)
			return
		}
		pub, err := p256JWK(p.PublicKey)
		if err != nil {
			_ = w.WriteError(varlink.NewError("org.varlink.service.InvalidParameter", "parameter", "jwk_pub"))
			return
		}
		wit, err := es256JWT(tenantKey,
			map[string]string{"alg": "ES256", "typ": "wit+jwt", "kid": kid},
			map[string]any{
				"iss": broker + "/tenants/" + tenant,
				"sub": "spiffe://" + tenant + "." + stamp + "/machine/" + machine,
				"aud": []string{p.Audience},
				"iat": now.Unix(),
				"exp": now.Add(time.Hour).Unix(),
				"jti": "fixture",
				"cnf": map[string]any{"jwk": pub},
			})
		if err != nil {
			_ = w.WriteError(varlink.NewError("com.amutable.IdentityAgent.Failed", "error", err.Error()))
			return
		}
		_ = w.WriteReply(map[string]any{"wit": wit, "expires_in": int64(time.Hour / time.Second)})
	})
	srv := &varlink.Server{Handler: &mux}
	go func() { _ = srv.Serve(listener) }()
	return uri, nil
}

func run(out string) error {
	tenantKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()

	dir, err := os.MkdirTemp("", "quarry-worker-fixture-") //nolint:forbidigo // fresh private directory
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }() //nolint:forbidigo // our own temporary directory
	agent, err := startAgent(dir, tenantKey, now)
	if err != nil {
		return err
	}

	// The signing transport sends through http.DefaultTransport.
	capture := &captureTransport{}
	http.DefaultTransport = capture
	cred, err := wimseagent.NewCred(wimseagent.ID{WitAudience: audience, Provider: agent}, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: &wimseagent.Transport{WitCred: cred}}
	reqURL := publicURL + "/machine-repos/" + tenant + "/" + machine + "/1.root.json"
	resp, err := client.Get(reqURL) //nolint:noctx // one-shot script
	if err != nil {
		return err
	}
	_ = resp.Body.Close() // empty body from captureTransport
	header := capture.header

	jwk := jose.JSONWebKey{Key: &tenantKey.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"}
	data, err := json.MarshalIndent(map[string]any{
		"now":            now.Unix(),
		"url":            reqURL,
		"jwks":           map[string]any{"keys": []any{jwk}},
		"wit":            header.Get("Workload-Identity-Token"),
		"signatureInput": header.Get("Signature-Input"),
		"signature":      header.Get("Signature"),
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, append(data, '\n'), 0o644) //nolint:forbidigo // path given by the user
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <go-signed-read.json>\n", os.Args[0])
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		log.Fatal(err)
	}
}
