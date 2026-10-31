// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/shogo82148/go-sfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/cryptoext"
)

// Test keys from RFC 9421 Appendix B.1.

// test-key-rsa (B.1.1).
const rfcRSAKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP
BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd
JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75
jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI
lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ
SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56
vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE
CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW
+m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA
yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR
Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J
YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM
cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw
DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1
mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT
qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67
B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv
9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn
f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo
81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa
/2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG
IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m
qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P
WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ
EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=
-----END RSA PRIVATE KEY-----`

// test-key-rsa-pss (B.1.2), from its JWK form: the PEM form uses the
// RSASSA-PSS OID, which crypto/x509 can't parse.
var rfcRSAPSSKeyJWK = map[string]string{
	"n": "r4tmm3r20Wd_PbqvP1s2-QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct-Lh1GH45x28Rw3Ry53mm-oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL-Wokqltd11nqqzi-bJ9cvSKADYdUAAN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4aOT9v6d-nb4bnNkQVklLQ3fVAvJm-xdDOp9LCNCN48V2pnDOkFV6-U9nV5oyc6XI2w",
	"e": "AQAB",
	"d": "lAfIqfpCYomVShfAKnwf2lD9I0wKjkHsCtZCif4kAlwQqqW6N-tIL3bdOR-VWf0Q1ZBIDtpO91UrG7pansyrPERbNrRJlPiYEyPTHkCT1nD-l2isuiyGLNBNnFoKfBgA4KAbPJZQatFIV9Cn34JSHnpN5-2ehreGBYHtkwHFtlmzeF3yu5bqRcqOhx8lkYmBzDAEUFyyXjknU5-WjAT9DzuG0MpOTkcU1EnjnIjyVBZLUB5Lxm8puyq8hH8B_E5LNC-1oc8j-tDy98UvRTTiYvZvs87cGCFxg0LijNhg7CE3g9piNqB6DzMgA9MHSOwcElVtfKdYfo4H3OHZXsSmEQ",
	"p": "5V-6ISI5yEaCFXm-fk1EM2xwAWekePVCAyvr9QbTlFOCZwt9WwjUjhtKRusi5Uq-IYZ_tq2WRE4As4b_FHEMtp2AER43IcvmXPqKFBoUktVDS7dThIHrsnRi1U7dHqVdwiMEMe5jxKNgnsKLpnq-4NyhoS6OeWu1SFozG9J9xQk",
	"q": "w-wIde17W5Y0Cphp3ZZ0uM8OUq1AkrV2IKauqYHaDxAT32EM4ci2MMER2nIUEo4g_42lW0zYouFFqONwv0-HyOsgPpdSqKRC5WLgn0VXabjaNcy6KhNPXeJ0AgtqdiDwPeJ2_L_eKwNWQ43RfdQBUquAwSd7SEmmQ8sViqB628M",
}

// test-key-ecc-p256 (B.1.3).
const rfcECCP256KeyD = "UpuF81l-kOxbjf7T4mNSv0r5tN67Gim7rnf6EFpcYDs"

// test-key-ed25519 (B.1.4).
const rfcEd25519KeyD = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU"

func b64url(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	require.NoError(t, err, "decode base64url")
	return b
}

func b64std(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err, "decode base64")
	return b
}

func rfcRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode([]byte(rfcRSAKeyPEM))
	require.NotNil(t, block, "decode PEM")
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err, "parse test-key-rsa")
	return key
}

func rfcRSAPSSKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	num := func(k string) *big.Int { return new(big.Int).SetBytes(b64url(t, rfcRSAPSSKeyJWK[k])) }
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: num("n"), E: int(num("e").Int64())},
		D:         num("d"),
		Primes:    []*big.Int{num("p"), num("q")},
	}
	require.NoError(t, key.Validate(), "validate test-key-rsa-pss")
	key.Precompute()
	return key
}

func rfcECCP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), b64url(t, rfcECCP256KeyD))
	require.NoError(t, err, "parse test-key-ecc-p256")
	return key
}

func rfcEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(b64url(t, rfcEd25519KeyD))
}

// rfcTestRequest returns the test-request message of RFC 9421 Appendix B.2.
func rfcTestRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://example.com/foo?param=Value&Pet=dog", strings.NewReader(`{"hello": "world"}`)) //nolint:noctx // test code
	require.NoError(t, err, "build test-request")
	req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:")
	return req
}

var rfcCreated = time.Unix(1618884473, 0)

// signatureFromHeader returns the signature bytes under label in h.
func signatureFromHeader(t *testing.T, h http.Header, label string) []byte {
	t.Helper()
	dict, err := sfv.DecodeDictionary(h.Values("Signature"))
	require.NoError(t, err, "parse Signature")
	sig, ok := dict.Get(label).Value.([]byte)
	require.True(t, ok, "Signature has a byte sequence for %q", label)
	return sig
}

// verifyRFC verifies an RFC 9421 format signature over base.
func verifyRFC(t *testing.T, pub crypto.PublicKey, opts crypto.SignerOpts, base string, sig []byte) {
	t.Helper()
	if ecPub, ok := pub.(*ecdsa.PublicKey); ok {
		size := (ecPub.Curve.Params().BitSize + 7) / 8
		require.Len(t, sig, 2*size, "ecdsa r||s signature length")
		der, err := asn1.Marshal(struct{ R, S *big.Int }{
			new(big.Int).SetBytes(sig[:size]),
			new(big.Int).SetBytes(sig[size:]),
		})
		require.NoError(t, err, "convert r||s to ASN.1")
		sig = der
	}
	verifier, err := cryptoext.NewVerifier(pub)
	require.NoError(t, err, "make verifier")
	ok, err := cryptoext.VerifyMessage(verifier, []byte(base), sig, opts)
	require.NoError(t, err, "verify signature")
	assert.True(t, ok, "signature verifies over base:\n%s", base)
}

var rfcPSSOpts = &rsa.PSSOptions{Hash: crypto.SHA512, SaltLength: rsa.PSSSaltLengthEqualsHash}

// B.2.1. SignRequest randomises the parameter order, so the base is built
// from the vector's exact parameter list.
func TestRFC9421_B21(t *testing.T) {
	key := rfcRSAPSSKey(t)
	input, base, err := signatureBase(nil, sfv.Parameters{
		{Key: "created", Value: int64(1618884473)},
		{Key: "keyid", Value: "test-key-rsa-pss"},
		{Key: "nonce", Value: "b3k2pp5k7z-50gnwp.yemd"},
	})
	require.NoError(t, err, "build signature base")

	const wantBase = `"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`
	assert.Equal(t, wantBase, string(base), "signature base")
	member, err := sfv.EncodeDictionary(sfv.Dictionary{{Key: "sig-b21", Item: input}})
	require.NoError(t, err, "encode Signature-Input")
	assert.Equal(t, `sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`, member, "Signature-Input")

	rfcSig := b64std(t, "d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==")
	verifyRFC(t, key.Public(), rfcPSSOpts, wantBase, rfcSig)
}

func TestRFC9421_SignRequest(t *testing.T) {
	for _, test := range []struct {
		name       string
		components []Component
		baseOpts   []BaseOption
		key        crypto.Signer
		keyID      string
		label      string
		verifyOpts crypto.SignerOpts
		wantInput  string
		wantBase   string
		// rfcSig is the published signature, which must verify over
		// wantBase.
		rfcSig string
		// exact means our signature must equal rfcSig byte for byte.
		exact bool
	}{
		{
			name: "B.2.3",
			components: []Component{
				Field("date"), Method(), Path(), Query(), Authority(),
				Field("content-type"), Field("content-digest"), Field("content-length"),
			},
			key:        rfcRSAPSSKey(t),
			keyID:      "test-key-rsa-pss",
			label:      "sig-b23",
			verifyOpts: rfcPSSOpts,
			wantInput:  `sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`,
			wantBase: `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@query": ?param=Value&Pet=dog
"@authority": example.com
"content-type": application/json
"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`,
			rfcSig: "bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yBiMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fUxN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5ZJzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==",
		},
		{
			name: "B.2.6",
			components: []Component{
				Field("date"), Method(), Path(), Authority(),
				Field("content-type"), Field("content-length"),
			},
			key:        rfcEd25519Key(t),
			keyID:      "test-key-ed25519",
			label:      "sig-b26",
			verifyOpts: crypto.Hash(0),
			wantInput:  `sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`,
			wantBase: `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@authority": example.com
"content-type": application/json
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`,
			rfcSig: "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==",
			exact:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			b, err := NewBase(append([]BaseOption{WithComponents(test.components...), WithoutAlg(), WithoutNonce()}, test.baseOpts...)...)
			require.NoError(t, err, "NewBase")
			ids := make([]string, len(test.components))
			for i, c := range test.components {
				ids[i] = c.String()
			}

			// SignRequest randomises the order, so check the vector with
			// its own order.
			req := rfcTestRequest(t)
			resolved, err := b.resolve(requestMessage{req})
			require.NoError(t, err, "resolve")
			input, base, err := signatureBase(orderAs(t, resolved, ids), sfv.Parameters{
				{Key: "created", Value: rfcCreated.Unix()},
				{Key: "keyid", Value: test.keyID},
			})
			require.NoError(t, err, "build signature base")
			assert.Equal(t, test.wantBase, string(base), "signature base")
			member, err := sfv.EncodeDictionary(sfv.Dictionary{{Key: test.label, Item: input}})
			require.NoError(t, err, "encode Signature-Input")
			assert.Equal(t, test.wantInput, member, "Signature-Input")

			rfcSig := b64std(t, test.rfcSig)
			verifyRFC(t, test.key.Public(), test.verifyOpts, test.wantBase, rfcSig)
			if test.exact {
				alg, opts, err := chooseAlgorithm(test.key.Public(), nil)
				require.NoError(t, err, "chooseAlgorithm")
				sig, err := alg.SignMessage(test.key, base, opts)
				require.NoError(t, err, "SignMessage")
				assert.Equal(t, rfcSig, sig, "signature matches RFC")
			}

			label, err := b.SignRequest(test.key, req,
				WithCreated(rfcCreated), WithKeyID(test.keyID), WithSigLabel(test.label))
			require.NoError(t, err, "SignRequest")
			assert.Equal(t, test.label, label, "returned label")
			got := signatureInput(t, req.Header, label)
			assert.ElementsMatch(t, ids, coveredIDs(t, got), "covered components")
			assert.ElementsMatch(t, []string{"created", "keyid"}, paramKeys(got.Parameters), "parameters")
			assert.Equal(t, rfcCreated.Unix(), got.Parameters.Get("created"), "created")
			assert.Equal(t, test.keyID, got.Parameters.Get("keyid"), "keyid")
			verifyRFC(t, test.key.Public(), test.verifyOpts, rebuildBase(t, b, req, label), signatureFromHeader(t, req.Header, label))
		})
	}
}

// RFC 9421 has no vector for the remaining algorithms, so check that each
// produces a valid signature in the RFC format over a known base.
func TestAlgorithms(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), nil)
	require.NoError(t, err, "generate P-384 key")

	for _, test := range []struct {
		name       string
		key        crypto.Signer
		signerOpts crypto.SignerOpts
		verifyOpts crypto.SignerOpts
		alg        string
	}{
		{"ed25519", rfcEd25519Key(t), nil, crypto.Hash(0), "ed25519"},
		{"ed25519-options", rfcEd25519Key(t), &ed25519.Options{}, crypto.Hash(0), "ed25519"},
		{"ecdsa-p256", rfcECCP256Key(t), nil, crypto.SHA256, "ecdsa-p256-sha256"},
		{"ecdsa-p384", p384, nil, crypto.SHA384, "ecdsa-p384-sha384"},
		{"rsa-pss-default", rfcRSAPSSKey(t), nil, rfcPSSOpts, "rsa-pss-sha512"},
		{"rsa-pss-salt-64", rfcRSAPSSKey(t), &rsa.PSSOptions{Hash: crypto.SHA512, SaltLength: 64}, rfcPSSOpts, "rsa-pss-sha512"},
		{"rsa-v1_5", rfcRSAKey(t), crypto.SHA256, crypto.SHA256, "rsa-v1_5-sha256"},
	} {
		t.Run(test.name, func(t *testing.T) {
			b, err := NewBase(WithComponents(Method(), TargetURI()), WithoutNonce())
			require.NoError(t, err, "NewBase")

			req, err := http.NewRequest(http.MethodGet, "https://repo.example.com/metadata/1.root.json", nil) //nolint:noctx // test code
			require.NoError(t, err, "NewRequest")
			opts := []SignOption{WithCreated(rfcCreated), WithKeyID("k")}
			if test.signerOpts != nil {
				opts = append(opts, WithSignerOpts(test.signerOpts))
			}
			label, err := b.SignRequest(test.key, req, opts...)
			require.NoError(t, err, "SignRequest")

			input := signatureInput(t, req.Header, label)
			assert.ElementsMatch(t, []string{`"@method"`, `"@target-uri"`}, coveredIDs(t, input), "covered components")
			assert.ElementsMatch(t, []string{"alg", "created", "keyid"}, paramKeys(input.Parameters), "parameters")
			assert.Equal(t, test.alg, input.Parameters.Get("alg"), "alg")
			base := rebuildBase(t, b, req, label)
			assert.Contains(t, base, "\"@target-uri\": https://repo.example.com/metadata/1.root.json\n", "signature base")
			sig := signatureFromHeader(t, req.Header, label)
			verifyRFC(t, test.key.Public(), test.verifyOpts, base, sig)

			if test.alg == "rsa-v1_5-sha256" {
				// PKCS #1 v1.5 is deterministic.
				digest := crypto.SHA256.New()
				digest.Write([]byte(base))
				want, err := rsa.SignPKCS1v15(nil, rfcRSAKey(t), crypto.SHA256, digest.Sum(nil))
				require.NoError(t, err, "SignPKCS1v15")
				assert.Equal(t, want, sig, "rsa-v1_5-sha256 signature")
			}
		})
	}
}
