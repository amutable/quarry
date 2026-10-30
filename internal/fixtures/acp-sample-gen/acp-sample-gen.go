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
	"net/http/httptest"
	"net/url"
	"os"
	"time"

	"snai.pe/go-varlink"

	"go.amutable.dev/quarry/internal/identityagent"
)

const (
	broker   = "https://wit-broker.test"
	tenant   = "acme"
	stamp    = "test.example"
	machine  = "0123456789abcdef0123456789abcdef"
	audience = "urn:amutable:quarry-worker"
	kid      = "tenant-key"
)

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

// rawJWK returns the JWK of an uncompressed P-256 point.
func rawJWK(raw []byte) map[string]string {
	return map[string]string{"kty": "EC", "crv": "P-256", "x": b64(raw[1:33]), "y": b64(raw[33:])}
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
			Audience  string `json:"audience"`
			PublicKey string `json:"public_key"`
		}
		if err := c.Unmarshal(&p); err != nil {
			_ = w.WriteError(err)
			return
		}
		pub, err := base64.RawURLEncoding.DecodeString(p.PublicKey)
		if err != nil || len(pub) != 65 {
			_ = w.WriteError(varlink.NewError("org.varlink.service.InvalidParameter", "parameter", "public_key"))
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
				"cnf": map[string]any{"jwk": rawJWK(pub)},
			})
		if err != nil {
			_ = w.WriteError(varlink.NewError("com.amutable.IdentityAgent.Failed", "error", err.Error()))
			return
		}
		_ = w.WriteReply(map[string]any{"token": wit, "expires_in": int64(time.Hour / time.Second)})
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

	var header http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		header = r.Header.Clone()
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: &identityagent.Transport{
		Audience:  audience,
		Host:      u.Host,
		SocketURI: agent,
	}}
	reqURL := srv.URL + "/machine-id/" + machine + "/1.root.json"
	resp, err := client.Get(reqURL) //nolint:noctx // one-shot script
	if err != nil {
		return err
	}
	_ = resp.Body.Close() // empty body from the capture handler

	tenantPub, err := tenantKey.PublicKey.Bytes()
	if err != nil {
		return err
	}
	jwk := rawJWK(tenantPub)
	jwk["kid"], jwk["alg"], jwk["use"] = kid, "ES256", "sig"
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
