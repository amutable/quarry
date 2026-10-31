// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package httpsig

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/shogo82148/go-sfv"
)

// Component is one covered component identifier: either a derived component
// ("@method", ...) or an HTTP field (lowercased name), plus its parameters.
// Components are comparable values; the zero Component is invalid.
type Component struct {
	kind componentKind
	req  bool
}

// componentKind is the type-specific part of a [Component]. Implementations
// must be comparable so that Component is.
type componentKind interface {
	// name returns the component name, such as "@method" or "content-type".
	name() string
	// params returns the kind's own identifier parameters.
	params() sfv.Parameters
	validate() error
	// resolve returns the component's value, or false if m doesn't have it.
	resolve(m message) (value string, present bool, err error)
}

// FromRequest returns c with the ";req" parameter, taking its value from the
// request a response answers. [Base.SignRequest] rejects it with
// [ErrResponseOnlyComponent].
func (c Component) FromRequest() Component {
	c.req = true
	return c
}

// item returns the component identifier as an sf-string item with its
// parameters.
func (c Component) item() sfv.Item {
	if c.kind == nil {
		return sfv.Item{Value: ""}
	}
	var params sfv.Parameters
	if c.req {
		params = append(params, sfv.Parameter{Key: "req", Value: true})
	}
	params = append(params, c.kind.params()...)
	return sfv.Item{Value: c.kind.name(), Parameters: params}
}

// String returns the serialised component identifier as it appears in the
// signature base and Signature-Input, e.g. `"content-digest";key="sha-256"`.
func (c Component) String() string {
	s, err := sfv.EncodeItem(c.item())
	if err != nil {
		// Only an invalid component (rejected by NewBase) gets here.
		return strconv.Quote(c.kind.name()) + ";<invalid>"
	}
	return s
}

func (c Component) validate() error {
	err := errors.New("empty component")
	if c.kind != nil {
		err = c.kind.validate()
	}
	if err != nil {
		return componentErr(c, fmt.Errorf("%w: %w", ErrInvalidComponent, err))
	}
	return nil
}

func (c Component) resolve(m message) (string, bool, error) {
	if c.req {
		var err error
		if m, err = m.related(); err != nil {
			return "", false, err
		}
	}
	return c.kind.resolve(m)
}

// derived is a derived component without parameters (RFC 9421 section 2.2).
type derived struct {
	id    string
	value func(m message) (string, error)
}

func (d *derived) name() string           { return d.id }
func (d *derived) params() sfv.Parameters { return nil }
func (d *derived) validate() error        { return nil }

func (d *derived) resolve(m message) (string, bool, error) {
	value, err := d.value(m)
	return value, err == nil, err
}

// fromRequest adapts a request-derived component's value function.
func fromRequest(value func(req *http.Request) (string, error)) func(message) (string, error) {
	return func(m message) (string, error) {
		req, err := m.request()
		if err != nil {
			return "", err
		}
		return value(req)
	}
}

var (
	derivedMethod = &derived{"@method", fromRequest(func(req *http.Request) (string, error) {
		return cmp.Or(req.Method, http.MethodGet), nil
	})}
	derivedTargetURI     = &derived{"@target-uri", fromRequest(RequestTargetURI)}
	derivedAuthority     = &derived{"@authority", fromRequest(RequestAuthority)}
	derivedScheme        = &derived{"@scheme", fromRequest(RequestScheme)}
	derivedRequestTarget = &derived{"@request-target", fromRequest(func(req *http.Request) (string, error) {
		// Matches the request-target net/http writes for CONNECT.
		if req.Method == http.MethodConnect && req.URL.Path == "" {
			if req.URL.Opaque != "" {
				return req.URL.Opaque, nil
			}
			return cmp.Or(req.Host, req.URL.Host), nil
		}
		return req.URL.RequestURI(), nil
	})}
	derivedPath = &derived{"@path", fromRequest(func(req *http.Request) (string, error) {
		return cmp.Or(req.URL.EscapedPath(), "/"), nil
	})}
	derivedQuery = &derived{"@query", fromRequest(func(req *http.Request) (string, error) {
		return "?" + req.URL.RawQuery, nil
	})}
	derivedStatus = &derived{"@status", func(m message) (string, error) {
		status, err := m.statusCode()
		if err != nil {
			return "", err
		}
		return strconv.Itoa(status), nil
	}}
)

// Method returns the "@method" derived component.
func Method() Component { return Component{kind: derivedMethod} }

// TargetURI returns the "@target-uri" derived component.
func TargetURI() Component { return Component{kind: derivedTargetURI} }

// Authority returns the "@authority" derived component.
func Authority() Component { return Component{kind: derivedAuthority} }

// Scheme returns the "@scheme" derived component.
func Scheme() Component { return Component{kind: derivedScheme} }

// RequestTarget returns the "@request-target" derived component.
func RequestTarget() Component { return Component{kind: derivedRequestTarget} }

// Path returns the "@path" derived component.
func Path() Component { return Component{kind: derivedPath} }

// Query returns the "@query" derived component.
func Query() Component { return Component{kind: derivedQuery} }

// Status returns the "@status" derived component. It is valid in a [Base],
// but [Base.SignRequest] rejects it with [ErrResponseOnlyComponent].
func Status() Component { return Component{kind: derivedStatus} }

var defaultPorts = map[string]string{
	"http":  "80",
	"https": "443",
}

// RequestScheme returns the request's "@scheme" value as defined by RFC 9421.
func RequestScheme(req *http.Request) (string, error) {
	scheme := strings.ToLower(req.URL.Scheme)
	if scheme == "" {
		return "", fmt.Errorf("%w: request URL has no scheme", ErrMissingComponent)
	}
	return scheme, nil
}

// RequestAuthority returns the request's "@authority" value as defined by RFC
// 9421 and normalised per RFC 9110 section 4.2.3.
func RequestAuthority(req *http.Request) (string, error) {
	host := strings.ToLower(cmp.Or(req.Host, req.URL.Host))
	if host == "" {
		return "", fmt.Errorf("%w: request has no host", ErrMissingComponent)
	}
	if port := (&url.URL{Host: host}).Port(); port == defaultPorts[strings.ToLower(req.URL.Scheme)] {
		host = strings.TrimSuffix(host, ":"+port)
	}
	return strings.TrimSuffix(host, ":"), nil
}

// RequestTargetURI returns the request's "@target-uri" value as defined by RFC
// 9421.
func RequestTargetURI(req *http.Request) (string, error) {
	scheme, err := RequestScheme(req)
	if err != nil {
		return "", err
	}
	authority, err := RequestAuthority(req)
	if err != nil {
		return "", err
	}
	return scheme + "://" + authority + req.URL.RequestURI(), nil
}
