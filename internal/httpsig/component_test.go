// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package httpsig

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComponentString(t *testing.T) {
	for _, test := range []struct {
		component Component
		want      string
	}{
		{Method(), `"@method"`},
		{TargetURI(), `"@target-uri"`},
		{Authority(), `"@authority"`},
		{Scheme(), `"@scheme"`},
		{RequestTarget(), `"@request-target"`},
		{Path(), `"@path"`},
		{Query(), `"@query"`},
		{Status(), `"@status"`},
		{Field("Content-Type"), `"content-type"`},
		{Field("example-dict", Key("a")), `"example-dict";key="a"`},
		{Field("example-dict", Structured()), `"example-dict";sf`},
		{Field("example-dict", StructuredAs(SFDictionary)), `"example-dict";sf`},
		{Field("example-header", ByteSequence()), `"example-header";bs`},
		{Field("expires", Trailer()), `"expires";tr`},
		{Field("signature", Key("sig1")).FromRequest(), `"signature";req;key="sig1"`},
		{Method().FromRequest(), `"@method";req`},
		{Field("x", ByteSequence(), Trailer()), `"x";bs;tr`},
		{Field("x", Trailer(), ByteSequence()), `"x";bs;tr`},
	} {
		assert.Equal(t, test.want, test.component.String(), "String()")
	}
}

func TestComponentComparable(t *testing.T) {
	// Using a Component as a map key panics if any kind is not comparable.
	seen := map[Component]bool{}
	for _, c := range []Component{
		Method(), TargetURI(), Authority(), Scheme(), RequestTarget(), Path(), Query(), Status(),
		Field("x"),
		Field("x", Key("a")),
		Field("x", Structured()),
		Field("x", StructuredAs(SFList)),
		Field("x", ByteSequence()),
		Field("x", Trailer()),
		Method().FromRequest(),
	} {
		assert.False(t, seen[c], "%s is distinct", c)
		seen[c] = true
	}
	assert.Equal(t, Field("content-digest", Key("sha-256")), Field("Content-Digest", Key("sha-256")), "same field")
	assert.NotEqual(t, Field("content-digest"), Field("content-digest", Key("sha-256")), "different params")
	assert.NotEqual(t, Method(), Method().FromRequest(), "req")
	assert.NotEqual(t, Component{}, Method(), "zero component")
	assert.Equal(t, Field("content-digest", Structured()), Field("content-digest", StructuredAs(SFDictionary)),
		"Structured looks up the type when the field is built")
}

func TestFieldEncodingLastWins(t *testing.T) {
	assert.Equal(t, Field("x", ByteSequence()), Field("x", Key("a"), Structured(), ByteSequence()), "last encoding wins")
	assert.Equal(t, Field("x", Key("a")), Field("x", ByteSequence(), Key("a")), "last encoding wins")
}

// componentErrors returns the components of the *ComponentErrors in err.
func componentErrors(t *testing.T, err, target error) []Component {
	t.Helper()
	var joined interface{ Unwrap() []error }
	errs := []error{err}
	if errors.As(err, &joined) {
		errs = joined.Unwrap()
	}
	var components []Component
	for _, err := range errs {
		var cerr *ComponentError
		if errors.As(err, &cerr) && errors.Is(cerr, target) {
			components = append(components, cerr.Component)
		}
	}
	return components
}

func TestNewBaseInvalidComponents(t *testing.T) {
	bad := []Component{
		{},
		Field("@method"),
		Field("bad name"),
		Field("x", Key("A")),
		Field("x-unknown", Structured()),
		Field("x", StructuredAs(SFType(42))),
		Field("bad name").FromRequest(),
	}
	_, err := NewBase(WithComponents(Method()), WithComponents(bad[:3]...), WithOptionalComponents(bad[3:]...))
	require.ErrorIs(t, err, ErrInvalidComponent, "NewBase with invalid components")
	assert.ElementsMatch(t, bad, componentErrors(t, err, ErrInvalidComponent), "every invalid component is reported")

	// Field("") has the same identifier as the zero Component.
	_, err = NewBase(WithComponents(Field("")))
	require.ErrorIs(t, err, ErrInvalidComponent, "NewBase with empty field name")
}

func TestNewBaseValidComponents(t *testing.T) {
	_, err := NewBase(WithComponents(
		Method(), TargetURI(), Authority(), Scheme(), RequestTarget(), Path(), Query(), Status(),
		Field("content-digest", Structured()),
		Field("content-digest", Key("sha-256")),
		Field("example-header", ByteSequence()),
		Field("expires", Trailer()),
		Field("signature", Key("sig1")).FromRequest(),
		Method().FromRequest(),
	))
	require.NoError(t, err, "NewBase")

	_, err = NewBase()
	require.NoError(t, err, "NewBase without components")
}

func TestWithComponentsOverride(t *testing.T) {
	components := []Component{Method(), Path()}
	opt := WithComponents(components...)
	components[0] = Query()

	b, err := NewBase(
		opt,
		WithComponents(Field("content-type"), Method(), Field("x", StructuredAs(SFList))),
		WithOptionalComponents(Field("Content-Type"), Field("a")),
		WithComponents(Field("a"), Field("x", StructuredAs(SFDictionary))),
		WithOptionalComponents(Method().FromRequest()),
	)
	require.NoError(t, err, "NewBase")
	assert.Equal(t, map[string]coveredComponent{
		`"@method"`:      {Component: Method()},
		`"@path"`:        {Component: Path()},
		`"content-type"`: {Component: Field("content-type"), optional: true},
		`"x";sf`:         {Component: Field("x", StructuredAs(SFDictionary))},
		`"a"`:            {Component: Field("a")},
		`"@method";req`:  {Component: Method().FromRequest(), optional: true},
	}, b.components, "later components replace earlier ones with the same identifier, unaffected by later changes to the caller's slice")
}

func resolveRequest(t *testing.T, req *http.Request, opts ...BaseOption) ([]resolvedComponent, error) {
	t.Helper()
	b, err := NewBase(opts...)
	require.NoError(t, err, "NewBase")
	return b.resolve(requestMessage{req})
}

func resolveOne(t *testing.T, req *http.Request, c Component) (string, error) {
	t.Helper()
	resolved, err := resolveRequest(t, req, WithComponents(c))
	if err != nil {
		return "", err
	}
	require.Len(t, resolved, 1, "resolved components")
	return resolved[0].value, nil
}

func newRequest(t *testing.T, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil) //nolint:noctx // test code
	require.NoError(t, err, "NewRequest")
	return req
}

// RFC 9421 section 2.1 examples.
func TestResolveFields(t *testing.T) {
	req := newRequest(t, http.MethodGet, "https://www.example.com/")
	req.Header["X-Ows-Header"] = []string{"   Leading and trailing whitespace.   "}
	req.Header["Cache-Control"] = []string{"max-age=60", "   must-revalidate"}
	req.Header["Example-Dict"] = []string{" a=1,    b=2;x=1;y=2,   c=(a   b   c)"}
	req.Header["Example-Dict2"] = []string{"  a=1, b=2;x=1;y=2, c=(a   b    c), d"}
	req.Header["Example-Header"] = []string{"value, with, lots", "of, commas"}
	req.Header["X-Empty-Header"] = []string{""}
	req.Header["Example-List"] = []string{"a,  b;x=1", "   (c   d)"}
	req.Header["Example-Item"] = []string{` "x";a=?0 `}
	req.Trailer = http.Header{"Expires": {"Wed, 9 Nov 2022 07:28:00 GMT"}}

	for _, test := range []struct {
		component Component
		want      string
	}{
		{Field("x-ows-header"), "Leading and trailing whitespace."},
		{Field("cache-control"), "max-age=60, must-revalidate"},
		{Field("example-dict"), "a=1,    b=2;x=1;y=2,   c=(a   b   c)"},
		{Field("x-empty-header"), ""},
		{Field("example-dict", StructuredAs(SFDictionary)), "a=1, b=2;x=1;y=2, c=(a b c)"},
		{Field("example-dict2", Key("a")), "1"},
		{Field("example-dict2", Key("d")), "?1"},
		{Field("example-dict2", Key("b")), "2;x=1;y=2"},
		{Field("example-dict2", Key("c")), "(a b c)"},
		{Field("example-header"), "value, with, lots, of, commas"},
		{Field("example-header", ByteSequence()), ":dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:"},
		{Field("example-list", StructuredAs(SFList)), "a, b;x=1, (c d)"},
		{Field("example-item", StructuredAs(SFItem)), `"x";a=?0`},
		{Field("expires", Trailer()), "Wed, 9 Nov 2022 07:28:00 GMT"},
	} {
		got, err := resolveOne(t, req, test.component)
		require.NoError(t, err, "resolve %s", test.component)
		assert.Equal(t, test.want, got, "value of %s", test.component)
	}
}

func TestResolveStructuredInvalid(t *testing.T) {
	req := newRequest(t, http.MethodGet, "https://example.com/")
	req.Header.Set("Content-Digest", "not a dictionary!")
	for _, c := range []Component{
		Field("content-digest", Structured()),
		Field("content-digest", Key("sha-256")),
	} {
		_, err := resolveOne(t, req, c)
		require.ErrorIs(t, err, ErrInvalidComponent, "resolve %s", c)
		var cerr *ComponentError
		require.ErrorAs(t, err, &cerr, "resolve %s", c)
		assert.Equal(t, c, cerr.Component, "ComponentError.Component")
	}
}

// RFC 9421 section 2.2 examples.
func TestResolveDerived(t *testing.T) {
	for _, test := range []struct {
		method, url string
		host        string
		component   Component
		want        string
	}{
		{"POST", "https://www.example.com/path?param=value", "", Method(), "POST"},
		{"", "https://www.example.com/", "", Method(), "GET"},
		{"POST", "https://www.example.com/path?param=value", "", TargetURI(), "https://www.example.com/path?param=value"},
		{"GET", "https://www.example.com/path#frag", "", TargetURI(), "https://www.example.com/path"},
		{"GET", "HTTPS://WWW.Example.COM:443/Path", "", TargetURI(), "https://www.example.com/Path"},
		{"POST", "https://www.example.com/path?param=value", "", Authority(), "www.example.com"},
		{"GET", "https://www.example.com:443/", "", Authority(), "www.example.com"},
		{"GET", "http://www.example.com:80/", "", Authority(), "www.example.com"},
		{"GET", "http://www.example.com:443/", "", Authority(), "www.example.com:443"},
		{"GET", "https://www.example.com:8443/", "", Authority(), "www.example.com:8443"},
		{"GET", "https://[::1]:443/", "", Authority(), "[::1]"},
		{"GET", "https://[::1]/", "", Authority(), "[::1]"},
		{"GET", "https://www.example.com/", "Other.Example.com:443", Authority(), "other.example.com"},
		{"POST", "http://www.example.com/path?param=value", "", Scheme(), "http"},
		{"POST", "https://www.example.com/path?param=value", "", RequestTarget(), "/path?param=value"},
		{"CONNECT", "https://www.example.com:80", "", RequestTarget(), "www.example.com:80"},
		{"GET", "https://www.example.com/path?param=value", "", Path(), "/path"},
		{"GET", "https://www.example.com", "", Path(), "/"},
		{"GET", "https://www.example.com/a%2Fb", "", Path(), "/a%2Fb"},
		{"GET", "https://www.example.com/path?param=value&foo=bar&baz=bat%2Dman", "", Query(), "?param=value&foo=bar&baz=bat%2Dman"},
		{"POST", "https://www.example.com/path?queryString", "", Query(), "?queryString"},
		{"GET", "https://www.example.com/path", "", Query(), "?"},
		{"GET", "https://www.example.com:/", "", Authority(), "www.example.com"},
	} {
		req := newRequest(t, test.method, test.url)
		req.Method = test.method
		if test.host != "" {
			req.Host = test.host
		}
		got, err := resolveOne(t, req, test.component)
		require.NoError(t, err, "resolve %s for %s %s", test.component, test.method, test.url)
		assert.Equal(t, test.want, got, "value of %s for %s %s", test.component, test.method, test.url)
	}
}

func TestResolveMissing(t *testing.T) {
	req := newRequest(t, http.MethodGet, "https://example.com/")
	req.Header.Set("Content-Digest", "sha-256=:AAAA:")

	for _, c := range []Component{
		Field("content-type"),
		Field("content-digest", Key("sha-512")),
		Field("expires", Trailer()),
	} {
		_, err := resolveOne(t, req, c)
		require.ErrorIs(t, err, ErrMissingComponent, "resolve %s", c)
	}

	resolved, err := resolveRequest(t, req,
		WithComponents(Method()),
		WithOptionalComponents(
			Field("content-type"),
			Field("content-digest", Key("sha-512")),
			Field("content-digest", Key("sha-256")),
			Field("expires", Trailer()),
		),
	)
	require.NoError(t, err, "resolve optional components")
	assert.ElementsMatch(t, []resolvedComponent{
		{component: Method(), value: http.MethodGet},
		{component: Field("content-digest", Key("sha-256")), value: ":AAAA:"},
	}, resolved, "absent optional components are dropped")
}

func TestResolveResponseOnly(t *testing.T) {
	req := newRequest(t, http.MethodGet, "https://example.com/")
	req.Header.Set("Signature", "sig1=:AAAA:")
	for _, c := range []Component{Status(), Field("signature", Key("sig1")).FromRequest(), Method().FromRequest()} {
		_, err := resolveOne(t, req, c)
		require.ErrorIs(t, err, ErrResponseOnlyComponent, "resolve %s", c)
	}
}

func TestResolveCRLF(t *testing.T) {
	req := newRequest(t, http.MethodGet, "https://example.com/")
	req.Header["X-Bad"] = []string{"a\r\nb"}
	_, err := resolveOne(t, req, Field("x-bad"))
	require.ErrorIs(t, err, ErrInvalidComponent, "value with CR/LF")

	req.Method = "GET\n"
	_, err = resolveOne(t, req, Method())
	require.ErrorIs(t, err, ErrInvalidComponent, "method with LF")
}

func TestResolveSpecialFields(t *testing.T) {
	req := newRequest(t, http.MethodGet, "https://example.com/")
	_, err := resolveOne(t, req, Field("host"))
	require.ErrorIs(t, err, ErrInvalidComponent, "host")
	require.ErrorContains(t, err, "@authority", "host error points to @authority")

	for _, name := range []string{"transfer-encoding", "trailer"} {
		_, err := resolveOne(t, req, Field(name))
		require.ErrorIs(t, err, ErrInvalidComponent, "resolve %s", name)
	}
}

type testBody struct{}

func (testBody) Read([]byte) (int, error) { return 0, nil }
func (testBody) Close() error             { return nil }

func TestResolveContentLength(t *testing.T) {
	for _, test := range []struct {
		name          string
		method        string
		body          bool
		contentLength int64
		chunked       bool
		want          string // empty means missing
	}{
		{"known length", "POST", true, 18, false, "18"},
		{"unknown length", "POST", true, -1, false, ""},
		{"body with zero length", "POST", true, 0, false, ""},
		{"chunked", "POST", true, 18, true, ""},
		{"no body POST", "POST", false, 0, false, "0"},
		{"no body PUT", "PUT", false, 0, false, "0"},
		{"no body GET", "GET", false, 0, false, ""},
		{"no body DELETE", "DELETE", false, 0, false, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := newRequest(t, test.method, "https://example.com/")
			// Header Content-Length is ignored, as net/http ignores it.
			req.Header.Set("Content-Length", "1234")
			if test.body {
				req.Body = testBody{}
			}
			req.ContentLength = test.contentLength
			if test.chunked {
				req.TransferEncoding = []string{"chunked"}
			}

			got, err := resolveOne(t, req, Field("content-length"))
			if test.want == "" {
				require.ErrorIs(t, err, ErrMissingComponent, "content-length")
				return
			}
			require.NoError(t, err, "content-length")
			assert.Equal(t, test.want, got, "content-length")
		})
	}
}
