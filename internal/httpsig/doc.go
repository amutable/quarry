// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// Package httpsig implements the generation of [RFC 9421] HTTP Message
// Signatures using [crypto.Signer].
//
// When signing [http.Request], users should first create a [Base] instance,
// which acts as an immutable "template" for signature. [Base.SignRequest] can
// then be used to used to sign individual [net/http.Request]s. [Transport]
// does the same for every request sent through an [net/http.Client].
//
// TODO: Signing of [net/http.Response] is not yet implemented.
// TODO: Verification is not implemented.
//
// [RFC 9421]: https://www.rfc-editor.org/rfc/rfc9421
package httpsig
