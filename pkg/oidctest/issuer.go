/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Stand up a simple OIDC endpoint. You can provide a list of subjects available
// to select during the OAuth flow. If the list of subjects is empty, the issuer
// will always create tokens for the subject "test-subject".
func NewIssuer(t *testing.T, subjects []string) (jose.Signer, string) {
	t.Helper()

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate RSA key %v", err)
	}
	jwk := jose.JSONWebKey{
		Algorithm: string(jose.RS256),
		Key:       pk,
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jwk.Key,
	}, nil)
	if err != nil {
		t.Fatalf("jose.NewSigner() = %v", err)
	}

	// Populated below, but we need to capture it first.
	oidcMux := http.NewServeMux()
	oidcServer := httptest.NewServer(oidcMux)
	testIssuer := oidcServer.URL

	oidcMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		t.Log("Handling request for openid-configuration.")
		if err := json.NewEncoder(w).Encode(struct {
			Issuer        string `json:"issuer"`
			JWKSURI       string `json:"jwks_uri"`
			AuthzEndpoint string `json:"authorization_endpoint"`
			TokenEndpoint string `json:"token_endpoint"`
		}{
			Issuer:        testIssuer,
			JWKSURI:       testIssuer + "/keys",
			AuthzEndpoint: testIssuer + "/authz",
			TokenEndpoint: testIssuer + "/token",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	oidcMux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		t.Log("Handling request for jwks.")
		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				jwk.Public(),
			},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// code stores information sent inside the `code` OAuth parameter.
	type code struct {
		ClientID      string `json:"client_id"`
		Nonce         string `json:"nonce"`
		Subject       string `json:"subject"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}

	oidcMux.HandleFunc("/authz", func(w http.ResponseWriter, r *http.Request) {
		t.Log("Handling request for authz.")
		redirectURL, err := url.Parse(r.URL.Query().Get("redirect_uri"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		subject := r.URL.Query().Get("subject")
		if subject == "" && len(subjects) == 0 {
			// There are no subjects available, revert to a default value.
			subject = "test-subject"
		}

		if subject == "" {
			// Render the subject selection form.
			writeSubjectSelector(w, r.URL.Query(), subjects)
			return
		}

		// Rely on `code` as a mechanism to encode information required by the token
		// endpoint.
		c, err := json.Marshal(code{
			ClientID:      r.URL.Query().Get("client_id"),
			Nonce:         r.URL.Query().Get("nonce"),
			Subject:       subject,
			Email:         r.URL.Query().Get("email"),
			EmailVerified: r.URL.Query().Has("email"),
			Name:          r.URL.Query().Get("name"),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		v := url.Values{
			"state": {r.URL.Query().Get("state")},
			"code":  {base64.StdEncoding.EncodeToString(c)},
		}
		redirectURL.RawQuery = v.Encode()

		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	})

	oidcMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		t.Log("Handling request for token.")

		rawCode, err := base64.StdEncoding.DecodeString(r.FormValue("code"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var c code
		if err := json.Unmarshal(rawCode, &c); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		token, err := jwt.Signed(signer).Claims(struct {
			jwt.Claims `json:",inline"` // nolint:revive // unknown option 'inline' in JSON tag

			Nonce         string `json:"nonce,omitempty"`
			Email         string `json:"email,omitempty"`
			EmailVerified bool   `json:"email_verified,omitempty"`
			Name          string `json:"name,omitempty"`
		}{
			Claims: jwt.Claims{
				Issuer:   testIssuer,
				IssuedAt: jwt.NewNumericDate(time.Now()),
				Expiry:   jwt.NewNumericDate(time.Now().Add(60 * time.Minute)),
				Subject:  c.Subject,
				Audience: jwt.Audience{c.ClientID},
			},
			Nonce:         c.Nonce,
			Email:         c.Email,
			EmailVerified: c.EmailVerified,
			Name:          c.Name,
		}).CompactSerialize()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(struct {
			IdToken     string `json:"id_token"`
			TokenType   string `json:"token_type"`
			AccessToken string `json:"access_token"`
		}{
			IdToken:     token,
			TokenType:   "Bearer",
			AccessToken: "garbage",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	t.Cleanup(oidcServer.Close)

	return signer, testIssuer
}

// writeSubjectSelector prints out the a message to reach out to us with your
// customerID to get access to the platform
func writeSubjectSelector(w http.ResponseWriter, v url.Values, subjects []string) {
	w.Header().Add("Content-Type", "text/html")

	const tpl = `
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>Select a subject</title>
	</head>
	<body>
		<form>
			<input type="hidden" name="client_id" value="{{ .client_id }}" />
			<input type="hidden" name="state" value="{{ .state }}" />
			<input type="hidden" name="nonce" value="{{ .nonce }}" />
			<input type="hidden" name="redirect_uri" value="{{ .redirect_uri }}" />
			<input type="text" name="email" placeholder="Email" />
			<input type="text" name="name" placeholder="Name" />
			<select name="subject">
				{{- range .subjects}}
					<option>{{ . }}</option>
				{{- end}}
			</select>
			<button type="submit">Submit</button>
		<form>
	</body>
</html>`

	t, err := template.New("webpage").Parse(tpl)
	if err != nil {
		log.Print("http handler: failed to parse template")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, map[string]interface{}{
		"subjects":     subjects,
		"client_id":    v.Get("client_id"),
		"nonce":        v.Get("nonce"),
		"redirect_uri": v.Get("redirect_uri"),
		"state":        v.Get("state"),
	})
	if err != nil {
		log.Print("http handler: failed to template message")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
}
